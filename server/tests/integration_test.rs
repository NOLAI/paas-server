use actix_web::{test, App};
use paas_server::application::sessions::{start_session, end_session};
use paas_server::application::transcrypt::{pseudonymize};
use paas_server::access_rules::{AccessRules, AuthenticatedUser};
use paas_server::session_storage::InMemorySessionStorage;
use libpep::distributed::systems::PEPSystem;
use actix_web::web::Data;
use std::sync::Arc;
use libpep::high_level::contexts::{PseudonymizationContext, EncryptionContext};
use libpep::high_level::data_types::EncryptedPseudonym;
use serde_json::json;

#[actix_web::test]
async fn test_start_session_and_pseudonymize() {
    let access_rules = AccessRules { allow: vec![] };
    let session_storage: Arc<dyn SessionStorage> = Arc::new(InMemorySessionStorage::new());
    let pep_system = PEPSystem::new_dummy(); // Assuming a dummy implementation for testing

    let app = test::init_service(
        App::new()
            .app_data(Data::new(access_rules))
            .app_data(Data::new(session_storage.clone()))
            .app_data(Data::new(pep_system.clone()))
            .service(
                web::scope("/sessions")
                    .route("/start", web::post().to(start_session))
                    .route("/end", web::post().to(end_session)),
            )
            .route("/pseudonymize", web::post().to(pseudonymize))
    )
    .await;

    // Test starting a session
    let req = test::TestRequest::post()
        .uri("/sessions/start")
        .to_request();
    let resp: StartSessionResponse = test::call_and_read_body_json(&app, req).await;
    assert!(!resp.session_id.is_empty());

    // Test pseudonymization
    let pseudonymization_request = json!({
        "encrypted_pseudonym": EncryptedPseudonym::new_dummy(), // Assuming a dummy implementation for testing
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
    assert!(!resp.encrypted_pseudonym.is_empty());
}
