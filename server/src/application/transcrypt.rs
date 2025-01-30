use crate::access_rules::{AccessRules, AuthenticatedUser};
use crate::session_storage::SessionStorage;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder};
use libpep::distributed::systems::PEPSystem;
use log::{info, warn};
use paas_common::transcrypt::{
    PseudonymizationBatchRequest, PseudonymizationBatchResponse, PseudonymizationRequest,
    PseudonymizationResponse,
};

pub async fn pseudonymize(
    req: HttpRequest,
    body: Bytes,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
) -> impl Responder {
    let session_storage = session_storage.get_ref();
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .unwrap();
    let request = serde_json::from_slice::<PseudonymizationRequest>(&body).unwrap();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "{:?} tried, but was not allowed to pseudonymize from {:?} to {:?}",
            user.username, request.domain_from.0, request.domain_to.0
        );
        return HttpResponse::Forbidden().body("Pseudonymization not allowed");
    }

    let sessions = session_storage
        .get_sessions_for_user(user.username.to_string())
        .expect("Failed to get sessions");

    if !sessions.contains(&request.session_to) {
        warn!(
            "{:?} tried to pseudonymize to an invalid decryption context",
            user.username
        );
        return HttpResponse::Forbidden().body("Decryption context not allowed");
    }

    let msg_out = pep_system.pseudonymize(
        &request.encrypted_pseudonym,
        &pep_system.pseudonymization_info(
            &request.domain_from,
            &request.domain_to,
            Some(&request.session_from),
            Some(&request.session_to),
        ),
    );

    info!(
        "{:?} pseudonymized from {:?} to {:?}",
        user.username, request.domain_from.0, request.domain_to.0
    );

    HttpResponse::Ok().json(PseudonymizationResponse {
        encrypted_pseudonym: msg_out,
    })
}

pub async fn pseudonymize_batch(
    req: HttpRequest,
    body: Bytes,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
) -> impl Responder {
    let session_storage = session_storage.get_ref();
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .unwrap();
    let request = serde_json::from_slice::<PseudonymizationBatchRequest>(&body).unwrap();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "{:?} tried, but was not allowed to pseudonymize from {:?} to {:?}",
            user.username, request.domain_from.0, request.domain_to.0
        );
        return HttpResponse::Forbidden().body("Pseudonymization not allowed");
    }

    let sessions = session_storage
        .get_sessions_for_user(user.username.to_string())
        .expect("Failed to get sessions");

    if !sessions.contains(&request.session_to) {
        warn!(
            "{:?} tried to pseudonymize to an invalid decryption context",
            user.username
        );
        return HttpResponse::Forbidden().body("Decryption context not allowed");
    }

    let mut encrypted_pseudonyms = request.encrypted_pseudonyms.clone();

    let mut rng = rand::thread_rng();
    let msg_out = pep_system.pseudonymize_batch(
        &mut encrypted_pseudonyms,
        &pep_system.pseudonymization_info(
            &request.domain_from,
            &request.domain_to,
            Some(&request.session_from),
            Some(&request.session_to),
        ),
        &mut rng,
    );

    info!(
        "{:?} batch-pseudonymized {:?} pseudonyms from {:?} to {:?}",
        user.username,
        request.encrypted_pseudonyms.len(),
        request.domain_from.0,
        request.domain_to.0
    );

    HttpResponse::Ok().json(PseudonymizationBatchResponse {
        encrypted_pseudonyms: Vec::from(msg_out),
    })
}

pub async fn rekey() -> impl Responder {
    HttpResponse::Ok().body("Rekey")
}
