use actix_web::body::to_bytes;
use actix_web::dev::Service;
use actix_web::web::Data;
use actix_web::{test, web, App, HttpMessage};
use libpep::distributed::key_blinding::{BlindingFactor, SafeScalar};
use libpep::distributed::systems::PEPSystem;
use libpep::high_level::contexts::PseudonymizationDomain;
use libpep::high_level::data_types::{
    Attribute, Encryptable, Encrypted, EncryptedAttribute, EncryptedPseudonym, Pseudonym,
};
use libpep::high_level::keys::{
    AttributeSessionPublicKey, AttributeSessionSecretKey, PseudonymSessionPublicKey,
    PseudonymSessionSecretKey, PublicKey,
};
use libpep::high_level::ops::{decrypt, encrypt, EncryptedData};
use libpep::high_level::padding::{LongAttribute, LongPseudonym};
use libpep::high_level::secrets::{EncryptionSecret, PseudonymizationSecret};
use libpep::internal::arithmetic::ScalarNonZero;
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
    let pep_system = PEPSystem::new(
        PseudonymizationSecret::from("pseudonymization_secret".as_bytes().to_vec()),
        EncryptionSecret::from("encryption_secret".as_bytes().to_vec()),
        BlindingFactor::decode_from_hex(
            "b791602b934f8506c4d39600665034c5838e40653b991a5b100ba50139eaa605",
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

    // Verify we got the expected pseudonymized result
    // This value is computed using blinding factor b791602b934f8506c4d39600665034c5838e40653b991a5b100ba50139eaa605
    assert_eq!(
        pseudonymization_response.encrypted_pseudonym,
        Encrypted::from_base64("CNDEJ5Sy_dyMwJNAuTzWG5aipMKQrqHRhiF1VOpdaTNAwa4azSivSuVhIqYwkvApJZJcIOmD3J9WmtvLc2ekfw==").unwrap()
    );

    let mut rng = rand::thread_rng();

    // Session keys generated with peppy:
    // peppy generate-session-keys dbf0d6e82ea1147350c1c613ba4ef160e35f3572c681b62f6f01e4606a5f0b06 encryption_secret test_session
    let psk = PseudonymSessionPublicKey::from_hex(
        "5028d18fb336570e0b234615fb1f469f1f69d69d8ea29fdcac36178685a5982d",
    )
    .unwrap();
    let ssk = PseudonymSessionSecretKey::from(
        ScalarNonZero::decode_from_hex(
            "7baa1880e93968c336104d3559bd541f6399ca7b02bc93cf2cdfc7009fa9740a",
        )
        .unwrap(),
    );
    // peppy generate-session-keys 00f1c8be6e2f12c052d2d4ca5fb0fe216a304fb7b218a064f0560ff39359b809 encryption_secret test_session
    let ask = AttributeSessionPublicKey::from_hex(
        "82264282ac08c0a2d917ddefbb194817abaea393f0f526efd8d227f91e940418",
    )
    .unwrap();
    let assk = AttributeSessionSecretKey::from(
        ScalarNonZero::decode_from_hex(
            "044ef94ae87d4923c09383ee8e7ead2a1f498a9ed8d9c68df1d282952423330a",
        )
        .unwrap(),
    );

    // Create some encrypted test data (simulated from client)
    // In a real scenario, this would be properly encrypted data from a client
    let test_data: Vec<EncryptedData> = vec![
        // Test with short pseudonym and short attribute
        (
            vec![encrypt(
                &Pseudonym::from_bytes(b"short_pseudo\0\0\0\0"),
                &psk,
                &mut rng,
            )],
            vec![encrypt(
                &Attribute::from_bytes(b"short_attribute\0"),
                &ask,
                &mut rng,
            )],
        ),
        // Test with long pseudonym and long attributes
        (
            LongPseudonym::from_string_padded(
                "This is a very long pseudonym that exceeds 16 bytes",
            )
            .unwrap()
            .0
            .iter()
            .map(|p| encrypt(p, &psk, &mut rng))
            .collect::<Vec<EncryptedPseudonym>>(),
            LongAttribute::from_string_padded("This is test data with a long attribute value")
                .unwrap()
                .0
                .iter()
                .map(|d| encrypt(d, &ask, &mut rng))
                .collect::<Vec<EncryptedAttribute>>(),
        ),
        // Test with pseudonym only
        (
            vec![encrypt(
                &Pseudonym::from_bytes(b"test_pseudonym2\0"),
                &psk,
                &mut rng,
            )],
            vec![],
        ),
        // Test with attributes only
        (
            vec![],
            vec![
                encrypt(
                    &Attribute::from_bytes(b"first_attr\0\0\0\0\0\0"),
                    &ask,
                    &mut rng,
                ),
                encrypt(
                    &Attribute::from_bytes(b"second_attr\0\0\0\0\0"),
                    &ask,
                    &mut rng,
                ),
            ],
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
    assert_eq!(transcryption_response.encrypted.len(), 4);

    // Expected attributes for verification
    let expected_all_attributes = vec![
        Attribute::from_bytes(b"short_attribute\0"),
        Attribute::from_bytes(b"first_attr\0\0\0\0\0\0"),
        Attribute::from_bytes(b"second_attr\0\0\0\0\0"),
    ];
    let long_attrs =
        LongAttribute::from_string_padded("This is test data with a long attribute value")
            .unwrap()
            .0;
    let mut expected_all_attributes = expected_all_attributes;
    expected_all_attributes.extend(long_attrs);

    // Verify counts: The transcrypt endpoint reorders items to break linkability
    // We expect:
    // - Total 6 pseudonyms (1 short + 4 long + 1 test_pseudonym2)
    // - Total 6 attributes (1 short + 3 long + 2 others)
    let total_pseudonyms: usize = transcryption_response
        .encrypted
        .iter()
        .map(|(ps, _)| ps.len())
        .sum();
    let total_attributes: usize = transcryption_response
        .encrypted
        .iter()
        .map(|(_, as_)| as_.len())
        .sum();

    assert_eq!(total_pseudonyms, 6, "Total pseudonym count mismatch");
    assert_eq!(total_attributes, 6, "Total attribute count mismatch");

    // Expected pseudonyms after transcryption from domain1 to domain2
    // These values are computed using:
    // - Blinding factor: b791602b934f8506c4d39600665034c5838e40653b991a5b100ba50139eaa605
    // - Pseudonymization secret: "pseudonymization_secret"
    // - Original pseudonyms: "short_pseudo", LongPseudonym("This is a very long..."), "test_pseudonym2"
    // After transcryption, the pseudonyms are transformed to new values in domain2
    let expected_transcrypted_pseudonyms: Vec<Pseudonym> = vec![
        Pseudonym::decode_from_hex(
            "cc951725293b675887172c1aea5c722bafb7033f9aa23bf87266dc123a048830",
        )
        .unwrap(),
        Pseudonym::decode_from_hex(
            "0e4cac079f52858a5a770e7b15708d6a55876d3577a7ac22050bee102ed15111",
        )
        .unwrap(),
        Pseudonym::decode_from_hex(
            "32999802ad46220aeaebbaf15933c3eec7221e67c7e39003a252c3b4073c9a73",
        )
        .unwrap(),
        Pseudonym::decode_from_hex(
            "0e60da98931d167f53fc6c3f9d0d2b9fa655e96e23e1cfe7ede81eb5cb66e85f",
        )
        .unwrap(),
        Pseudonym::decode_from_hex(
            "1c4468a94c762cbaca13bcb9ae4262138a9675dcac37d19ac85e8fdf2481507e",
        )
        .unwrap(),
        Pseudonym::decode_from_hex(
            "5e6a468be1ddff9ec4808f2e7cce5fa6aa32cdc9f9136b64adb96e2719517121",
        )
        .unwrap(),
    ];

    // Decrypt all pseudonyms and verify they match expected transcrypted values
    let mut decrypted_pseudonyms: Vec<Pseudonym> = Vec::new();
    for (pseudonyms, _) in &transcryption_response.encrypted {
        for p in pseudonyms {
            let decrypted = decrypt(p, &ssk);
            decrypted_pseudonyms.push(decrypted);
        }
    }

    // Sort both vectors to compare (since order is randomized)
    let mut decrypted_pseudonym_hashes: Vec<String> = decrypted_pseudonyms
        .iter()
        .map(|p| p.encode_as_hex())
        .collect();
    decrypted_pseudonym_hashes.sort();

    let mut expected_pseudonym_hashes: Vec<String> = expected_transcrypted_pseudonyms
        .iter()
        .map(|p| p.encode_as_hex())
        .collect();
    expected_pseudonym_hashes.sort();

    assert_eq!(
        decrypted_pseudonym_hashes, expected_pseudonym_hashes,
        "Transcrypted pseudonym values don't match expected"
    );

    // Decrypt all attributes and verify they match expected values (order may vary)
    let mut decrypted_attributes: Vec<Attribute> = Vec::new();
    for (_, attributes) in &transcryption_response.encrypted {
        for a in attributes {
            decrypted_attributes.push(decrypt(a, &assk));
        }
    }

    // Sort both vectors to compare (since order is randomized)
    let mut decrypted_bytes: Vec<[u8; 16]> = decrypted_attributes
        .iter()
        .map(|a| a.as_bytes().unwrap())
        .collect();
    decrypted_bytes.sort();

    let mut expected_bytes: Vec<[u8; 16]> = expected_all_attributes
        .iter()
        .map(|a| a.as_bytes().unwrap())
        .collect();
    expected_bytes.sort();

    assert_eq!(
        decrypted_bytes, expected_bytes,
        "Attribute values don't match"
    );
}
