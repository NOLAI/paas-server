use std::collections::HashSet;
use actix_web::{test, web, App, HttpMessage};
use paas_server::application::sessions::{start_session, end_session, StartSessionResponse};
use paas_server::application::transcrypt::{pseudonymize, PseudonymizationResponse};
use paas_server::access_rules::{AccessRules, AuthenticatedUser};
use paas_server::session_storage::{InMemorySessionStorage, SessionStorage};
use libpep::distributed::systems::PEPSystem;
use actix_web::web::Data;
use std::sync::Arc;
use libpep::distributed::key_blinding::{BlindingFactor, SafeScalar};
use libpep::high_level::contexts::{PseudonymizationContext, EncryptionContext};
use libpep::high_level::data_types::{Encrypted, EncryptedPseudonym};
use libpep::high_level::keys::{EncryptionSecret, PseudonymizationSecret};
use libpep::internal::arithmetic::ScalarNonZero;
use rand::rngs::OsRng;
use serde_json::json;

#[actix_web::test]
async fn test_start_session_and_pseudonymize() {
    let access_rules = AccessRules { allow: vec![] };
    let session_storage: Arc<dyn SessionStorage> = Arc::new(InMemorySessionStorage::new());
    let pep_system = PEPSystem::new(
        PseudonymizationSecret::from("pseudonymization_secret".as_bytes().to_vec()),
        EncryptionSecret::from("encryption_secret".as_bytes().to_vec()),
        BlindingFactor::decode_from_hex("5f5289d6909083257b9372c362a1905a0f0370181c5b75af812815513edcda0a").unwrap(),
    );

    let app = test::init_service(
        App::new()
            .app_data(Data::new(access_rules))
            .app_data(Data::new(session_storage.clone()))
            .app_data(Data::new(pep_system.clone()))
            .service(
                web::scope("/sessions")
                    .route("/start", web::post().to(start_session))
            )
            .route("/pseudonymize", web::post().to(pseudonymize))
    )
    .await;

    // Test starting a session
    let req = test::TestRequest::post()
        .uri("/sessions/start")
        .insert_header(("Authorization", "Bearer <your_jwt_token_here>"))
        .to_request();
    req.extensions_mut().insert(AuthenticatedUser {
        username: Arc::new("test_user".to_string()),
        usergroups: Arc::new(HashSet::from(["group1".to_string()])),
    });
    let resp: StartSessionResponse = test::call_and_read_body_json(&app, req).await.unwrap();

    // Test pseudonymization
    let pseudonymization_request = json!({
        "encrypted_pseudonym": EncryptedPseudonym::from_base64("nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==").unwrap(),
        "pseudonym_context_from": PseudonymizationContext::from("context1"),
        "pseudonym_context_to": PseudonymizationContext::from("context2"),
        "enc_context": EncryptionContext::from("enc_context"),
        "dec_context": EncryptionContext::from("dec_context"),
    });

    let req = test::TestRequest::post()
        .uri("/pseudonymize")
        .set_json(&pseudonymization_request)
        .to_request();
    let resp: PseudonymizationResponse = test::call_and_read_body_json(&app, req).await;
    // assert!(!resp.encrypted_pseudonym.is_empty());
}
