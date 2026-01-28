use actix_web::body::to_bytes;
use actix_web::dev::Service;
use actix_web::web::Data;
use actix_web::{test, web, App, HttpMessage};
use libpep::arithmetic::scalars::ScalarNonZero;
use libpep::client::encrypt;
use libpep::client::prelude::{Attribute, EncryptedPseudonym, Pseudonym};
use libpep::data::padding::Padded;
use libpep::data::records::EncryptedRecord;
use libpep::data::simple::ElGamalEncrypted;
use libpep::factors::{EncryptionSecret, PseudonymizationDomain, PseudonymizationSecret};
use libpep::keys::distribution::BlindingFactor;
use libpep::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey, PublicKey,
};
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

#[actix_web::test]
async fn test_start_session_and_pseudonymize() {
    let auth_user = AuthInfo {
        username: "test".to_string(),
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
            "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a",
        )
        .unwrap(),
    );

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
                        "/pseudonymize",
                        web::post().to(pseudonymize::<EncryptedPseudonym>),
                    )
                    .route("/transcrypt", web::post().to(transcrypt::<EncryptedRecord>)),
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
    let req = test::TestRequest::post()
        .uri("/pseudonymize")
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

    assert_eq!(resp.status(), 200);
    let body = to_bytes(resp.into_body()).await.unwrap();
    let pseudonymization_response: PseudonymizationResponse<EncryptedPseudonym> =
        serde_json::from_slice(&body).unwrap();

    assert_eq!(pseudonymization_response.result, EncryptedPseudonym::from_base64("CNDEJ5Sy_dyMwJNAuTzWG5aipMKQrqHRhiF1VOpdaTNAwa4azSivSuVhIqYwkvApJZJcIOmD3J9WmtvLc2ekfw==").unwrap());

    let mut rng = rand::rng();

    // Generated with peppy using: generate-session-keys 40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a encryption_secret session_context
    // Public pseudonym global key: ae3bfc06e29d54875a5ed21fc95dd5717d49d16d89e26351289a2e30f06a0270
    // Secret pseudonym global key: 40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a
    // Same keys for now
    // Public attribute session key: ae3bfc06e29d54875a5ed21fc95dd5717d49d16d89e26351289a2e30f06a0270
    // Secret attribute session key: 40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a
    let psk_p = PseudonymSessionPublicKey::from_hex(
        "8a80494c8fb18a09abbd356ed6b32c050036234bb618f71ceb3ea84e3fd55751",
    )
    .unwrap();
    let _ssk_p = PseudonymSessionSecretKey::from(
        ScalarNonZero::from_hex("40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a")
            .unwrap(),
    );
    let psk_a = AttributeSessionPublicKey::from_hex(
        "8a80494c8fb18a09abbd356ed6b32c050036234bb618f71ceb3ea84e3fd55751",
    )
    .unwrap();
    let _ssk_a = AttributeSessionSecretKey::from(
        ScalarNonZero::from_hex("40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a")
            .unwrap(),
    );

    // Create some encrypted test data (simulated from client)
    // In a real scenario, this would be properly encrypted data from a client
    // Using Normal types (EncryptedPseudonym, EncryptedAttribute)
    let pseudonym1 = Pseudonym::from_string_padded("Test pseudo 1").unwrap();
    let attribute1 = Attribute::from_string_padded("Attribute 1").unwrap();

    // Create a single EncryptedData record (normal variant)
    let test_data = EncryptedRecord {
        pseudonyms: vec![encrypt(&pseudonym1, &psk_p, &mut rng)],
        attributes: vec![encrypt(&attribute1, &psk_a, &mut rng)],
    };

    // Test transcrypt with Normal variant (single encrypted data record)
    let req = test::TestRequest::post()
        .uri("/transcrypt")
        .set_json(json!({
            "domain_from": PseudonymizationDomain::from("domain1"),
            "domain_to": PseudonymizationDomain::from("domain2"),
            "session_from": start_session_response.session_id.clone(),
            "session_to": start_session_response.session_id.clone(),
            "encrypted": test_data
        }))
        .to_request();

    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();
    // Verify the response
    let status = resp.status();
    let body = to_bytes(resp.into_body()).await.unwrap();

    assert_eq!(status, 200);
    let transcryption_response: TranscryptionResponse<EncryptedRecord> =
        serde_json::from_slice(&body).unwrap();

    // Verify the structure of the returned data
    // Should have 1 pseudonym and 1 attribute (matching input structure)
    assert_eq!(transcryption_response.result.pseudonyms.len(), 1);
    assert_eq!(transcryption_response.result.attributes.len(), 1);
}
