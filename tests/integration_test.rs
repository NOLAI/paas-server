use actix_web::body::to_bytes;
use actix_web::dev::Service;
use actix_web::web::Data;
use actix_web::{test, web, App, HttpMessage};
use libpep::distributed::key_blinding::{BlindingFactor, SafeScalar};
use libpep::distributed::systems::PEPSystem;
use libpep::high_level::contexts::PseudonymizationDomain;
use libpep::high_level::data_types::{
    DataPoint, Encryptable, Encrypted, EncryptedDataPoint, EncryptedPseudonym, Pseudonym,
};
use libpep::high_level::keys::{
    EncryptionSecret, PseudonymizationSecret, PublicKey, SessionPublicKey, SessionSecretKey,
};
use libpep::high_level::ops::{decrypt, encrypt, EncryptedEntityData};
use libpep::internal::arithmetic::ScalarNonZero;
use paas_api::sessions::StartSessionResponse;
use paas_api::transcrypt::{PseudonymizationResponse, TranscryptionResponse};
use paas_server::access_rules::{AccessRules, Permission};
use paas_server::application::sessions::start_session;
use paas_server::application::transcrypt::{pseudonymize, transcrypt};
use paas_server::auth::core::AuthInfo;
use paas_server::session_storage::{InMemorySessionStorage, SessionStorage};
use serde_json::json;
use std::collections::HashSet;
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
    let session_storage: Box<dyn SessionStorage> = Box::new(InMemorySessionStorage::new(Duration::from_secs(10), 10));
    let pep_system = PEPSystem::new(
        PseudonymizationSecret::from("pseudonymization_secret".as_bytes().to_vec()),
        EncryptionSecret::from("encryption_secret".as_bytes().to_vec()),
        BlindingFactor::decode_from_hex(
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
                    .route("/pseudonymize", web::post().to(pseudonymize))
                    .route("/transcrypt", web::post().to(transcrypt)),
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
        "encrypted_pseudonym": EncryptedPseudonym::from_base64("nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==").unwrap(),
        "domain_from": PseudonymizationDomain::from("domain1"),
        "domain_to": PseudonymizationDomain::from("domain2"),
        "session_from": start_session_response.session_id,
        "session_to": start_session_response.session_id,
    }))
        .to_request();
    req.extensions_mut().insert(auth_user.clone());
    let resp = app.call(req).await.unwrap();
    let body = to_bytes(resp.into_body()).await.unwrap();
    let pseudonymization_response: PseudonymizationResponse =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(pseudonymization_response.encrypted_pseudonym, Encrypted::from_base64("MMAGtJdXoHVPlC_IMPOA7H8sluFIeIRHvTg_pmR3S0tsYjLMnWCOnJ3AjQIjPBcgz3-v7roDOrkxgTNbZv1vKw==").unwrap());

    let mut rng = rand::thread_rng();

    // TODO: We should use these keys in the above test cases too
    // Generated with peppy using: generate-session-keys 40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a encryption_secret session_context
    // Public global key: ae3bfc06e29d54875a5ed21fc95dd5717d49d16d89e26351289a2e30f06a0270
    // Secret global key: 40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a
    // Public session key: 1e98811ec579ac7f4e860547010e3df3ddda945016cd70334fc2611521d5732a
    // Secret session key: b2250470169b81abf9247d19d699d17bc506b0eab1e1ab9341449d43f1521601
    let psk = SessionPublicKey::from_hex(
        "1e98811ec579ac7f4e860547010e3df3ddda945016cd70334fc2611521d5732a",
    )
    .unwrap();
    let ssk = SessionSecretKey::from(
        ScalarNonZero::decode_from_hex(
            "b2250470169b81abf9247d19d699d17bc506b0eab1e1ab9341449d43f1521601",
        )
        .unwrap(),
    );

    // Create some encrypted test data (simulated from client)
    // In a real scenario, this would be properly encrypted data from a client
    let test_data: Vec<EncryptedEntityData> = vec![
        (
            Pseudonym::from_string_padded("Testing pseudonym 1")
                .iter()
                .map(|p| encrypt(p, &psk, &mut rng))
                .collect::<Vec<EncryptedPseudonym>>(),
            DataPoint::from_string_padded("Really long datapoint, could be json")
                .iter()
                .map(|d| encrypt(d, &psk, &mut rng))
                .collect::<Vec<EncryptedDataPoint>>(),
        ),
        (
            Pseudonym::from_string_padded("Testing pseudonym 2")
                .iter()
                .map(|p| encrypt(p, &psk, &mut rng))
                .collect::<Vec<EncryptedPseudonym>>(),
            DataPoint::from_string_padded("Also a really long datapoint, could be json")
                .iter()
                .map(|d| encrypt(d, &psk, &mut rng))
                .collect::<Vec<EncryptedDataPoint>>(),
        ),
    ];

    // Test transcrypt
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
    assert_eq!(resp.status(), 200);
    let body = to_bytes(resp.into_body()).await.unwrap();
    let transcryption_response: TranscryptionResponse = serde_json::from_slice(&body).unwrap();

    // Verify we got back the expected number of encrypted items
    assert_eq!(transcryption_response.encrypted.len(), 2);

    let decrypted = transcryption_response
        .encrypted
        .iter()
        .map(|(psue, datap)| {
            (
                psue.iter()
                    .map(|p| decrypt(p, &ssk).encode_as_hex())
                    .collect::<Vec<String>>()
                    .join(""),
                DataPoint::to_string_padded(
                    datap
                        .iter()
                        .map(|d| decrypt(d, &ssk))
                        .collect::<Vec<DataPoint>>()
                        .as_slice(),
                )
                .unwrap(),
            )
        })
        .collect::<Vec<(String, String)>>();

    let expected_data = vec![
        (
            "8e54ac16e300c590dc56fdf3de24fc8883a3939241137857d4a273b9884a7c0fac55624f61ba08645b9f232877dcaade532242d950ed021e92dbaa5d40a5d91a".to_string(),
            "Really long datapoint, could be json".to_string()
        ),
        (
            "8e54ac16e300c590dc56fdf3de24fc8883a3939241137857d4a273b9884a7c0f7e8c90902e9b9b23aa469455b30a73e29739ea4204ce7c5227e15ba64b01c047".to_string(),
            "Also a really long datapoint, could be json".to_string()
        )
    ];

    // Create a HashSet from both collections for order-independent comparison
    let decrypted_set: HashSet<_> = decrypted.into_iter().collect();
    let expected_set: HashSet<_> = expected_data.into_iter().collect();

    assert_eq!(decrypted_set, expected_set);
}
