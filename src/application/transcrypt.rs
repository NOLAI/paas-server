use crate::access_rules::{AccessRules, AuthenticatedUser};
use crate::session_storage::SessionStorage;
use actix_web::web::{Bytes, Data};
use log::{info, warn, error};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder};
use libpep::distributed::systems::PEPSystem;
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationContext};
use libpep::high_level::data_types::{Encrypted, EncryptedPseudonym};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PseudonymizationResponse {
    encrypted_pseudonym: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PseudonymizationRequest {
    encrypted_pseudonym: String,
    pseudonym_context_from: PseudonymizationContext,
    pseudonym_context_to: PseudonymizationContext,
    enc_context: EncryptionContext,
    dec_context: EncryptionContext,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PseudonymizationBatchRequest {
    encrypted_pseudonyms: Vec<String>,
    pseudonym_context_from: PseudonymizationContext,
    pseudonym_context_to: PseudonymizationContext,
    enc_context: EncryptionContext,
    dec_context: EncryptionContext,
}

#[derive(Serialize, Deserialize)]
pub struct PseudonymizationBatchResponse {
    encrypted_pseudonyms: Vec<String>,
}

pub async fn pseudonymize(
    req: HttpRequest,
    body: Bytes,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
) -> impl Responder {
    info!("Pseudonymize function called");
    let session_storage = session_storage.get_ref();
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .unwrap();
    let request = serde_json::from_slice::<PseudonymizationRequest>(&body).unwrap();

    if !access_rules.has_access(
        &user,
        &request.pseudonym_context_from,
        &request.pseudonym_context_to,
    ) {
        return HttpResponse::Forbidden().body("Pseudonymization not allowed");
    }

    let sessions = session_storage
        .get_sessions_for_user(user.username.to_string())
        .expect("Failed to get sessions");

    if !sessions.contains(&request.dec_context) {
        return HttpResponse::Forbidden().body("Decryption context not allowed");
    }

    let msg_in = EncryptedPseudonym::from_base64(&request.encrypted_pseudonym);
    if msg_in.is_none() {
        return HttpResponse::BadRequest().body("Invalid data");
    }
    let msg_out = pep_system.pseudonymize(
        &msg_in.unwrap(),
        &pep_system.pseudonymization_info(
            &request.pseudonym_context_from,
            &request.pseudonym_context_to,
            &request.enc_context,
            &request.dec_context,
        ),
    );

    HttpResponse::Ok().json(PseudonymizationResponse {
        encrypted_pseudonym: msg_out.to_base64(),
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

    if !access_rules.has_access(
        &user,
        &request.pseudonym_context_from,
        &request.pseudonym_context_to,
    ) {
        return HttpResponse::Forbidden().body("Pseudonymization not allowed");
    }

    let sessions = session_storage
        .get_sessions_for_user(user.username.to_string())
        .expect("Failed to get sessions");

    if !sessions.contains(&request.dec_context) {
        return HttpResponse::Forbidden().body("Decryption context not allowed");
    }

    let msg_in = request
        .encrypted_pseudonyms
        .iter()
        .map(|x| EncryptedPseudonym::from_base64(x))
        .collect::<Vec<Option<EncryptedPseudonym>>>();

    for msg in msg_in.iter() {
        if msg.is_none() {
            return HttpResponse::BadRequest().body("Invalid data");
        }
    }

    let mut msg_in = msg_in
        .iter()
        .map(|x| x.unwrap())
        .collect::<Vec<EncryptedPseudonym>>();
    let msg_in = msg_in.as_mut_slice();

    let mut rng = rand::thread_rng();
    let msg_out = pep_system.pseudonymize_batch(
        msg_in,
        &pep_system.pseudonymization_info(
            &request.pseudonym_context_from,
            &request.pseudonym_context_to,
            &request.enc_context,
            &request.dec_context,
        ),
        &mut rng,
    );

    HttpResponse::Ok().json(PseudonymizationBatchResponse {
        encrypted_pseudonyms: msg_out.iter().map(|x| x.encode_to_base64()).collect(),
    })
}

pub async fn rekey() -> impl Responder {
    HttpResponse::Ok().body("Rekey")
}
