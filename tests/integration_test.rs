use actix_web::body::to_bytes;
use actix_web::dev::Service;
use actix_web::web::Data;
use actix_web::{test, web, App, HttpMessage};
use libpep::client::encrypt;
use libpep::client::prelude::{Attribute, EncryptedAttribute, EncryptedPseudonym, Pseudonym};
use libpep::data::json::EncryptedPEPJSONValue;
use libpep::data::long::{
    LongAttribute, LongEncryptedAttribute, LongEncryptedPseudonym, LongPseudonym,
};
use libpep::data::padding::Padded;
use libpep::data::records::{EncryptedRecord, LongEncryptedRecord};
use libpep::data::simple::ElGamalEncrypted;
use libpep::factors::{EncryptionSecret, PseudonymizationDomain, PseudonymizationSecret};
use libpep::keys::distribution::BlindingFactor;
use libpep::keys::PublicKey;
use libpep::keys::{AttributeSessionPublicKey, PseudonymSessionPublicKey};
use libpep::transcryptor::DistributedTranscryptor;
use paas_api::sessions::StartSessionResponse;
use paas_api::transcrypt::{PseudonymizationResponse, TranscryptionResponse};
use paas_server::access_rules::{AccessRules, Permission};
use paas_server::application::sessions::start_session;
use paas_server::application::transcrypt::{pseudonymize, transcrypt};
use paas_server::auth::core::AuthInfo;
use paas_server::session_storage::{InMemorySessionStorage, SessionStorage};
use serde_json::json;
use std::time::Duration;

/// Creates the test app with all the necessary services configured
fn create_test_config() -> (
    AuthInfo,
    AccessRules,
    Box<dyn SessionStorage>,
    DistributedTranscryptor,
) {
    let auth_user = AuthInfo {
        name: "test".to_string(),
        sub: "test_sub".to_string(),
        groups: vec!["group1".to_string()],
    };
    let permission = Permission {
        usergroups: vec!["group1".to_string()],
        start: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        end: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        from: vec![PseudonymizationDomain::from("domain1")],
        to: vec![PseudonymizationDomain::from("domain2")],
    };
    let access_rules = AccessRules {
        allow: vec![permission],
    };
    let session_storage: Box<dyn SessionStorage> =
        Box::new(InMemorySessionStorage::new(Duration::from_secs(10), 10));
    let pep_system = DistributedTranscryptor::new(
        PseudonymizationSecret::from("pseudonymization_secret".as_bytes().to_vec()),
        EncryptionSecret::from("encryption_secret".as_bytes().to_vec()),
        BlindingFactor::from_hex(
            "b791602b934f8506c4d39600665034c5838e40653b991a5b100ba50139eaa605",
        )
        .unwrap(),
    );

    (auth_user, access_rules, session_storage, pep_system)
}

/// Session keys for testing
fn get_test_session_keys() -> (PseudonymSessionPublicKey, AttributeSessionPublicKey) {
    // Generated with peppy using: generate-session-keys 40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a encryption_secret session_context
    let psk_p = PseudonymSessionPublicKey::from_hex(
        "8a80494c8fb18a09abbd356ed6b32c050036234bb618f71ceb3ea84e3fd55751",
    )
    .unwrap();
    let psk_a = AttributeSessionPublicKey::from_hex(
        "8a80494c8fb18a09abbd356ed6b32c050036234bb618f71ceb3ea84e3fd55751",
    )
    .unwrap();
    (psk_p, psk_a)
}

#[actix_web::test]
async fn test_start_session_and_pseudonymize() {
    let (auth_user, access_rules, session_storage, pep_system) = create_test_config();

    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .app_data(Data::new(access_rules))
            .app_data(Data::new(session_storage))
            .app_data(Data::new(pep_system))
            .service(
                web::scope("")
                    .service(web::scope("sessions").route("/start", web::post().to(start_session)))
                    .route(
                        paas_api::paths::pseudonymize_path::<EncryptedPseudonym>().as_str(),
                        web::post().to(pseudonymize::<EncryptedPseudonym>),
                    ),
            ),
    )
    .await;

    // Start a session
    let req = test::TestRequest::post()
        .uri("/sessions/start")
        .to_request();
    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();
    let body = to_bytes(resp.into_body()).await.unwrap();
    let start_session_response: StartSessionResponse = serde_json::from_slice(&body).unwrap();

    // Test pseudonymization
    let pseudonymize_path = paas_api::paths::pseudonymize_path::<EncryptedPseudonym>();
    let req = test::TestRequest::post()
        .uri(&pseudonymize_path)
        .set_json(json!({
            "encrypted": EncryptedPseudonym::from_base64("nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==").unwrap(),
            "domain_from": PseudonymizationDomain::from("domain1"),
            "domain_to": PseudonymizationDomain::from("domain2"),
            "session_from": start_session_response.session_id,
            "session_to": start_session_response.session_id,
        }))
        .to_request();
    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();
    let body = to_bytes(resp.into_body()).await.unwrap();
    let pseudonymization_response: PseudonymizationResponse<EncryptedPseudonym> =
        serde_json::from_slice(&body).unwrap();

    // Verify we got the expected pseudonymized result
    // This value is computed using blinding factor b791602b934f8506c4d39600665034c5838e40653b991a5b100ba50139eaa605
    assert_eq!(
        pseudonymization_response.result,
        EncryptedPseudonym::from_base64("CNDEJ5Sy_dyMwJNAuTzWG5aipMKQrqHRhiF1VOpdaTNAwa4azSivSuVhIqYwkvApJZJcIOmD3J9WmtvLc2ekfw==").unwrap()
    );
}

#[actix_web::test]
async fn test_transcrypt_encrypted_record() {
    let (auth_user, access_rules, session_storage, pep_system) = create_test_config();
    let (psk_p, psk_a) = get_test_session_keys();
    let mut rng = rand::rng();

    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .app_data(Data::new(access_rules))
            .app_data(Data::new(session_storage))
            .app_data(Data::new(pep_system))
            .service(
                web::scope("")
                    .service(web::scope("sessions").route("/start", web::post().to(start_session)))
                    .route(
                        paas_api::paths::transcrypt_path::<EncryptedRecord>().as_str(),
                        web::post().to(transcrypt::<EncryptedRecord>),
                    ),
            ),
    )
    .await;

    // Start a session
    let req = test::TestRequest::post()
        .uri("/sessions/start")
        .to_request();
    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();
    let body = to_bytes(resp.into_body()).await.unwrap();
    let start_session_response: StartSessionResponse = serde_json::from_slice(&body).unwrap();

    // Create test data with EncryptedRecord (short pseudonym and attribute only)
    let pseudonym = Pseudonym::from_string_padded("short_pseudo").unwrap();
    let attribute = Attribute::from_string_padded("short_attr").unwrap();

    let test_record = EncryptedRecord {
        pseudonyms: vec![encrypt(&pseudonym, &psk_p, &mut rng)],
        attributes: vec![encrypt(&attribute, &psk_a, &mut rng)],
    };

    // Test transcrypt for EncryptedRecord
    let transcrypt_path = paas_api::paths::transcrypt_path::<EncryptedRecord>();
    let req = test::TestRequest::post()
        .uri(&transcrypt_path)
        .set_json(json!({
            "domain_from": PseudonymizationDomain::from("domain1"),
            "domain_to": PseudonymizationDomain::from("domain2"),
            "session_from": start_session_response.session_id.clone(),
            "session_to": start_session_response.session_id.clone(),
            "encrypted": test_record
        }))
        .to_request();

    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();

    // Verify the response
    assert_eq!(resp.status(), 200);
    let body = to_bytes(resp.into_body()).await.unwrap();
    let transcryption_response: TranscryptionResponse<EncryptedRecord> =
        serde_json::from_slice(&body).unwrap();

    // Verify we got back a transcrypted record with the expected structure
    assert_eq!(transcryption_response.result.pseudonyms.len(), 1);
    assert_eq!(transcryption_response.result.attributes.len(), 1);
}

#[actix_web::test]
async fn test_transcrypt_long_encrypted_record() {
    let (auth_user, access_rules, session_storage, pep_system) = create_test_config();
    let (psk_p, psk_a) = get_test_session_keys();
    let mut rng = rand::rng();

    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .app_data(Data::new(access_rules))
            .app_data(Data::new(session_storage))
            .app_data(Data::new(pep_system))
            .service(
                web::scope("")
                    .service(web::scope("sessions").route("/start", web::post().to(start_session)))
                    .route(
                        paas_api::paths::transcrypt_path::<LongEncryptedRecord>().as_str(),
                        web::post().to(transcrypt::<LongEncryptedRecord>),
                    ),
            ),
    )
    .await;

    // Start a session
    let req = test::TestRequest::post()
        .uri("/sessions/start")
        .to_request();
    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();
    let body = to_bytes(resp.into_body()).await.unwrap();
    let start_session_response: StartSessionResponse = serde_json::from_slice(&body).unwrap();

    // Create test data with LongEncryptedRecord (for data exceeding 16 bytes)
    let long_pseudonym =
        LongPseudonym::from_string_padded("This is a very long pseudonym that exceeds 16 bytes");
    let long_attribute = LongAttribute::from_string_padded("This is a very long attribute value");

    let encrypted_pseudonyms: Vec<EncryptedPseudonym> = long_pseudonym
        .0
        .iter()
        .map(|p| encrypt(p, &psk_p, &mut rng))
        .collect();

    let encrypted_attributes: Vec<EncryptedAttribute> = long_attribute
        .0
        .iter()
        .map(|a| encrypt(a, &psk_a, &mut rng))
        .collect();

    let test_record = LongEncryptedRecord {
        pseudonyms: vec![LongEncryptedPseudonym(encrypted_pseudonyms)],
        attributes: vec![LongEncryptedAttribute(encrypted_attributes)],
    };

    // Test transcrypt for LongEncryptedRecord
    let transcrypt_path = paas_api::paths::transcrypt_path::<LongEncryptedRecord>();
    let req = test::TestRequest::post()
        .uri(&transcrypt_path)
        .set_json(json!({
            "domain_from": PseudonymizationDomain::from("domain1"),
            "domain_to": PseudonymizationDomain::from("domain2"),
            "session_from": start_session_response.session_id.clone(),
            "session_to": start_session_response.session_id.clone(),
            "encrypted": test_record
        }))
        .to_request();

    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();

    // Verify the response
    assert_eq!(resp.status(), 200);
    let body = to_bytes(resp.into_body()).await.unwrap();
    let transcryption_response: TranscryptionResponse<LongEncryptedRecord> =
        serde_json::from_slice(&body).unwrap();

    // Verify we got back a transcrypted record with the expected structure
    assert_eq!(transcryption_response.result.pseudonyms.len(), 1);
    assert_eq!(transcryption_response.result.attributes.len(), 1);
    // LongPseudonym for 52 chars needs ceil(52/16) = 4 pseudonym chunks
    assert_eq!(transcryption_response.result.pseudonyms[0].0.len(), 4);
    // LongAttribute for 35 chars needs ceil(35/16) = 3 attribute chunks
    assert_eq!(transcryption_response.result.attributes[0].0.len(), 3);
}

#[actix_web::test]
async fn test_transcrypt_encrypted_pep_json() {
    let (auth_user, access_rules, session_storage, pep_system) = create_test_config();
    let (psk_p, _psk_a) = get_test_session_keys();
    let mut rng = rand::rng();

    let app = test::init_service(
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .app_data(Data::new(access_rules))
            .app_data(Data::new(session_storage))
            .app_data(Data::new(pep_system))
            .service(
                web::scope("")
                    .service(web::scope("sessions").route("/start", web::post().to(start_session)))
                    .route(
                        paas_api::paths::transcrypt_path::<EncryptedPEPJSONValue>().as_str(),
                        web::post().to(transcrypt::<EncryptedPEPJSONValue>),
                    ),
            ),
    )
    .await;

    // Start a session
    let req = test::TestRequest::post()
        .uri("/sessions/start")
        .to_request();
    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();
    let body = to_bytes(resp.into_body()).await.unwrap();
    let start_session_response: StartSessionResponse = serde_json::from_slice(&body).unwrap();

    // Create test data with EncryptedPEPJSONValue
    // EncryptedPEPJSONValue::Pseudonym expects a LongEncryptedPseudonym
    let pseudonym = Pseudonym::from_string_padded("json_pseudo_val").unwrap();
    let encrypted_pseudonym = encrypt(&pseudonym, &psk_p, &mut rng);
    let test_json = EncryptedPEPJSONValue::Pseudonym(encrypted_pseudonym);

    // Test transcrypt for EncryptedPEPJSONValue
    let transcrypt_path = paas_api::paths::transcrypt_path::<EncryptedPEPJSONValue>();
    let req = test::TestRequest::post()
        .uri(&transcrypt_path)
        .set_json(json!({
            "domain_from": PseudonymizationDomain::from("domain1"),
            "domain_to": PseudonymizationDomain::from("domain2"),
            "session_from": start_session_response.session_id.clone(),
            "session_to": start_session_response.session_id.clone(),
            "encrypted": test_json
        }))
        .to_request();

    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();

    // Verify the response
    assert_eq!(resp.status(), 200);
    let body = to_bytes(resp.into_body()).await.unwrap();
    let transcryption_response: TranscryptionResponse<EncryptedPEPJSONValue> =
        serde_json::from_slice(&body).unwrap();

    // Verify we got back a transcrypted JSON value of the expected type
    match transcryption_response.result {
        EncryptedPEPJSONValue::Pseudonym(_) => {
            // Expected - we sent an encrypted pseudonym, we should get one back
        }
        _ => panic!("Expected Pseudonym variant"),
    }
}
