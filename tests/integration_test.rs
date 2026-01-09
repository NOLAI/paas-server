use actix_web::body::to_bytes;
use actix_web::dev::Service;
use actix_web::web::Data;
use actix_web::{test, web, App, HttpMessage};
use libpep::arithmetic::scalars::ScalarNonZero;
use libpep::base::elgamal::{decrypt, encrypt};
use libpep::core::data::{Attribute, Encrypted, EncryptedPseudonym, Pseudonym};
use libpep::core::keys::{AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey, PseudonymSessionSecretKey, PublicKey};
use libpep::core::padding::Padded;
use libpep::core::transcryption::{
    EncryptionSecret, PseudonymizationDomain, PseudonymizationSecret,
};
use libpep::distributed::server::setup::BlindingFactor;
use libpep::distributed::server::transcryptor::PEPSystem;
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
use libpep::core::long::batch::LongEncryptedData;
use libpep::core::long::data::{LongAttribute, LongPseudonym, encrypt_long_pseudonym, encrypt_long_attribute};

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
    let pep_system = PEPSystem::new(
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
    println!("{}", pseudonymization_response.encrypted_pseudonym.to_base64());
    assert_eq!(pseudonymization_response.encrypted_pseudonym, Encrypted::from_base64("CNDEJ5Sy_dyMwJNAuTzWG5aipMKQrqHRhiF1VOpdaTNAwa4azSivSuVhIqYwkvApJZJcIOmD3J9WmtvLc2ekfw==").unwrap());

    let mut rng = rand::rng();

    // TODO: We should use these keys in the above test cases too
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
    let ssk_p = PseudonymSessionSecretKey::from(
        ScalarNonZero::from_hex("40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a")
            .unwrap(),
    );
    let psk_a = AttributeSessionPublicKey::from_hex(
        "8a80494c8fb18a09abbd356ed6b32c050036234bb618f71ceb3ea84e3fd55751",
    )
    .unwrap();
    let ssk_a = AttributeSessionSecretKey::from(
        ScalarNonZero::from_hex("40116e3e779af820137a7999b985a6fadbc9fbd44750cf1dce44c29ef3d3ce0a")
            .unwrap(),
    );

    // Create some encrypted test data (simulated from client)
    // In a real scenario, this would be properly encrypted data from a client
    let test_data: Vec<LongEncryptedData> = vec![
        (
            vec![encrypt_long_pseudonym(&LongPseudonym::from_string_padded("Testing pseudonym 1"), &psk_p, &mut rng)],
            vec![encrypt_long_attribute(&LongAttribute::from_string_padded("Really long Attribute, could be json"), &psk_a, &mut rng)],
        ),
        (
            vec![encrypt_long_pseudonym(&LongPseudonym::from_string_padded("Testing pseudonym 2"), &psk_p, &mut rng)],
            vec![encrypt_long_attribute(&LongAttribute::from_string_padded("Also a really long Attribute, could be json"), &psk_a, &mut rng)],
        ),
    ];

    println!("{:?}", test_data);
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
    let status = resp.status();
    let body = to_bytes(resp.into_body()).await.unwrap();
    if status != 200 {
        println!("Error response ({}): {}", status, String::from_utf8_lossy(&body));
    }
    assert_eq!(status, 200);
    let transcryption_response: TranscryptionResponse = serde_json::from_slice(&body).unwrap();

    // Verify we got back the expected number of encrypted items
    assert_eq!(transcryption_response.encrypted.len(), 2);
    println!("{:?}", transcryption_response.encrypted);

    for (psue, attri) in &transcryption_response.encrypted {
        for p in psue {
            println!("Psuedonym {:?}", Pseudonym { value: decrypt(p, &ssk_p) }.to_hex());
        }
        for a in attri {
            println!("Attribute {:?}", Attribute { value: decrypt(a, &ssk_a) }.to_string_padded().unwrap());
        }
    }

    let decrypted = transcryption_response
        .encrypted
        .iter()
        .map(|(psue, attri)| {
            (
                psue.iter()
                    .map(|p| Pseudonym { value: decrypt(p, &ssk_p) }.to_hex())
                    .collect::<Vec<String>>()
                    .join(""),
                {
                    attri
                        .iter()
                        .map(|d| {
                            let attr = Attribute { value: decrypt(d, &ssk_a) };
                            attr.to_string_padded().unwrap()
                        })
                        .collect::<Vec<String>>()
                        .concat()
                },
            )
        })
        .collect::<Vec<(String, String)>>();

    let expected_data = vec![
        (
            "8e54ac16e300c590dc56fdf3de24fc8883a3939241137857d4a273b9884a7c0fac55624f61ba08645b9f232877dcaade532242d950ed021e92dbaa5d40a5d91a".to_string(),
            "Really long Attribute, could be json".to_string()
        ),
        (
            "8e54ac16e300c590dc56fdf3de24fc8883a3939241137857d4a273b9884a7c0f7e8c90902e9b9b23aa469455b30a73e29739ea4204ce7c5227e15ba64b01c047".to_string(),
            "Also a really long Attribute, could be json".to_string()
        )
    ];

    // Create a HashSet from both collections for order-independent comparison
    let decrypted_set: HashSet<_> = decrypted.into_iter().collect();
    let expected_set: HashSet<_> = expected_data.into_iter().collect();

    assert_eq!(decrypted_set, expected_set);
}
