use std::collections::HashMap;
use libpep::distributed::key_blinding::{BlindedGlobalSecretKey, SafeScalar,};
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::high_level::data_types::{Encrypted, EncryptedPseudonym};
use libpep::high_level::keys::{GlobalPublicKey, PublicKey};
use mockito::{mock};
use paas_client::pseudonym_service::{PseudonymService, PseudonymServiceConfig};
use paas_client::transcryptor_client::TranscryptorConfig;

#[tokio::test]
async fn test_create_pep_client() {
    // Mock response for /session/start
    let _m = mock("GET", "/session/start")
        .with_status(200)
        .with_body(r#"{"session_id": "test_session", "key_share": "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a"}"#)
        .create();

    let config = PseudonymServiceConfig {
        blinded_global_secret_key: BlindedGlobalSecretKey::decode_from_hex("dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908").unwrap(),
        global_public_key: GlobalPublicKey::from_hex("3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62").unwrap(),
        transcryptors: vec![TranscryptorConfig {
            system_id: "test_system_1".to_string(),
            url: mockito::server_url(),
            auth_token: "test_token_1".to_string(),
        }, TranscryptorConfig {
            system_id: "test_system_2".to_string(),
            url: mockito::server_url(),
            auth_token: "test_token_2".to_string()}],
    };

    let mut service = PseudonymService::new(config);
    service.init().await;
    assert!(service.pep_crypto_client.is_some());
}

#[tokio::test]
async fn test_pseudonymize() {
    // Mock response for /session/start
    let _m1 = mock("GET", "/session/start")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(r#"{"session_id": "test_session", "key_share": "5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a"}"#)
        .create();

    // Mock response for /pseudonymize
    let _m2 = mock("POST", "/pseudonymize")
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(r#"{"encrypted_pseudonym": "gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA=="}"#)
        .create();

    let config = PseudonymServiceConfig {
        blinded_global_secret_key: BlindedGlobalSecretKey::decode_from_hex("dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908").unwrap(),
        global_public_key: GlobalPublicKey::from_hex("3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62").unwrap(),
        transcryptors: vec![TranscryptorConfig {
            system_id: "test_system_1".to_string(),
            url: mockito::server_url(),
            auth_token: "test_token_1".to_string(),
        }, TranscryptorConfig {
            system_id: "test_system_2".to_string(),
            url: mockito::server_url(),
            auth_token: "test_token_2".to_string()}],
    };


    let encrypted_pseudonym = EncryptedPseudonym::from_base64("nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==").unwrap();
    let sessions = HashMap::from([
        ("test_system_1".to_string(), EncryptionContext::from("session_1")),
        ("test_system_2".to_string(), EncryptionContext::from("session_2"))
    ]);
    let domain_from = PseudonymizationDomain::from("domain_1");
    let domain_to = PseudonymizationDomain::from("domain_2");

    let mut service = PseudonymService::new(config);
    let result = service.pseudonymize(&encrypted_pseudonym, &sessions, &domain_from, &domain_to).await;
    assert_eq!(result, EncryptedPseudonym::from_base64("gqmiHiFA8dMdNtbCgsJ-EEfT9fjTV91BrfcHKN57e2vaLR2_UJEVExd6o9tdZg7vKGQklYZwV3REOaOQedKtUA==").unwrap());
}
