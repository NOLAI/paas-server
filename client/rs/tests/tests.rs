use std::collections::HashMap;
use libpep::distributed::key_blinding::{BlindedGlobalSecretKey, SessionKeyShare};
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationContext};
use libpep::high_level::data_types::EncryptedPseudonym;
use libpep::high_level::keys::GlobalPublicKey;
use mockito::{mock, Matcher};
use paas_client::pseudonym_service::{PseudonymService, PseudonymServiceConfig};
use paas_client::transcryptor_client::TranscryptorConfig;
use rand_core::OsRng;

#[tokio::test]
async fn test_create_pep_client() {
    let _m = mock("GET", "/session/start")
        .with_status(200)
        .with_body(r#"{"session_id": "test_session", "key_share": "test_key_share"}"#)
        .create();

    let config = PseudonymServiceConfig {
        blinded_global_secret_key: BlindedGlobalSecretKey::from_hex("22e81de441de01e689873e5b7a0c0166f2").unwrap(),
        global_public_key: GlobalPublicKey::new(),
        transcryptors: vec![TranscryptorConfig {
            system_id: "test_system".to_string(),
            url: mockito::server_url(),
            jwt: "test_jwt".to_string(),
        }],
    };

    let mut service = PseudonymService::new(config);
    service.create_pep_client().await;
    assert!(service.pep_client.is_some());
}

#[tokio::test]
async fn test_pseudonymize() {
    let _m = mock("POST", "/pseudonymize")
        .with_status(200)
        .with_body(r#"{"encrypted_pseudonym": "new_encrypted_pseudonym"}"#)
        .create();

    let config = PseudonymServiceConfig {
        blinded_global_secret_key: BlindedGlobalSecretKey::from_hex("22e81de441de01e689873e5b7a0c0166f2").unwrap(),
        global_public_key: GlobalPublicKey::new(),
        transcryptors: vec![TranscryptorConfig {
            system_id: "test_system".to_string(),
            url: mockito::server_url(),
            jwt: "test_jwt".to_string(),
        }],
    };

    let service = PseudonymService::new(config);
    let encrypted_pseudonym = EncryptedPseudonym::from("test_encrypted_pseudonym");
    let ec_from = EncryptionContext::from("test_ec_from");
    let pc_from = PseudonymizationContext::from("test_pc_from");
    let pc_to = PseudonymizationContext::from("test_pc_to");

    let result = service.pseudonymize(&encrypted_pseudonym, &ec_from, &pc_from, &pc_to).await;
    assert_eq!(result, EncryptedPseudonym::from("new_encrypted_pseudonym"));
}

#[tokio::test]
async fn test_pseudonymize_batch() {
    let _m = mock("POST", "/pseudonymize_batch")
        .with_status(200)
        .with_body(r#"{"encrypted_pseudonyms": ["new_encrypted_pseudonym1", "new_encrypted_pseudonym2"]}"#)
        .create();

    let config = PseudonymServiceConfig {
        blinded_global_secret_key: BlindedGlobalSecretKey::from_hex("22e81de441de01e689873e5b7a0c0166f2").unwrap(),
        global_public_key: GlobalPublicKey::new(),
        transcryptors: vec![TranscryptorConfig {
            system_id: "test_system".to_string(),
            url: mockito::server_url(),
            jwt: "test_jwt".to_string(),
        }],
    };

    let service = PseudonymService::new(config);
    let encrypted_pseudonyms = vec![
        EncryptedPseudonym::from("test_encrypted_pseudonym1"),
        EncryptedPseudonym::from("test_encrypted_pseudonym2"),
    ];
    let ec_from = EncryptionContext::from("test_ec_from");
    let pc_from = PseudonymizationContext::from("test_pc_from");
    let pc_to = PseudonymizationContext::from("test_pc_to");

    let result = service.pseudonymize_batch(&encrypted_pseudonyms, &ec_from, &pc_from, &pc_to).await;
    assert_eq!(result, vec![
        EncryptedPseudonym::from("new_encrypted_pseudonym1"),
        EncryptedPseudonym::from("new_encrypted_pseudonym2"),
    ]);
}
