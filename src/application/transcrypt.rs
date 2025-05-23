use crate::access_rules::AccessRules;
use crate::auth::core::AuthInfo;
use crate::errors::PAASServerError;
use crate::session_storage::SessionStorage;
use actix_web::web::Data;
use actix_web::{web, HttpResponse, Responder};
use libpep::distributed::systems::PEPSystem;
use log::{info, warn};
use paas_api::transcrypt::{
    PseudonymizationBatchRequest, PseudonymizationBatchResponse, PseudonymizationRequest,
    PseudonymizationResponse, RekeyRequest, RekeyResponse, TranscryptionRequest,
    TranscryptionResponse,
};

pub async fn pseudonymize(
    item: web::Json<PseudonymizationRequest>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_storage = session_storage.get_ref();
    let request = item.into_inner();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "{} tried, but was not allowed to pseudonymize from {:?} to {:?}",
            user.username, request.domain_from, request.domain_to
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.0.clone(),
            to: request.domain_to.0.clone(),
        });
    }
    let session_valid = session_storage
        .session_exists(
            user.username.to_string(),
            request.session_to.clone().to_string(),
        )
        .map_err(|e| {
            warn!(
                "Failed to check if session exists for user {}: {}",
                user.username, e
            );
            PAASServerError::SessionError(Box::new(e))
        })?;

    if !session_valid {
        warn!(
            "{} tried to pseudonymize to an invalid decryption context: {:?}",
            user.username, request.session_to
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    let pseudonymization_info = pep_system.pseudonymization_info(
        &request.domain_from,
        &request.domain_to,
        Some(&request.session_from),
        Some(&request.session_to),
    );

    let msg_out = pep_system.pseudonymize(&request.encrypted_pseudonym, &pseudonymization_info);

    info!(
        "{:?} pseudonymized from {:?} to {:?}",
        user.username, request.domain_from.0, request.domain_to.0
    );

    Ok(HttpResponse::Ok().json(PseudonymizationResponse {
        encrypted_pseudonym: msg_out,
    }))
}

pub async fn pseudonymize_batch(
    item: web::Json<PseudonymizationBatchRequest>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_storage = session_storage.get_ref();

    let request = item.into_inner();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "{} tried, but was not allowed to pseudonymize from {} to {}",
            user.username, request.domain_from.0, request.domain_to.0
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.0.clone(),
            to: request.domain_to.0.clone(),
        });
    }

    let session_valid = session_storage
        .session_exists(
            user.username.to_string(),
            request.session_to.clone().to_string(),
        )
        .map_err(|e| {
            warn!(
                "Failed to check if session exists for user {}: {}",
                user.username, e
            );
            PAASServerError::SessionError(Box::new(e))
        })?;

    if !session_valid {
        warn!(
            "{} tried to pseudonymize to an invalid decryption context: {:?}",
            user.username, request.session_to
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    let mut encrypted_pseudonyms = request.encrypted_pseudonyms.clone();
    let mut rng = rand::thread_rng();

    let pseudonymization_info = pep_system.pseudonymization_info(
        &request.domain_from,
        &request.domain_to,
        Some(&request.session_from),
        Some(&request.session_to),
    );

    let msg_out =
        pep_system.pseudonymize_batch(&mut encrypted_pseudonyms, &pseudonymization_info, &mut rng);

    info!(
        "{} batch-pseudonymized {} pseudonyms from {:?} to {:?}",
        user.username,
        request.encrypted_pseudonyms.len(),
        request.domain_from,
        request.domain_to
    );

    Ok(HttpResponse::Ok().json(PseudonymizationBatchResponse {
        encrypted_pseudonyms: Vec::from(msg_out),
    }))
}

pub async fn rekey(
    item: web::Json<RekeyRequest>,
    _access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_storage = session_storage.get_ref();

    let request = item.into_inner();

    // TODO: check access rules!

    let session_valid = session_storage
        .session_exists(
            user.username.to_string(),
            request.session_to.clone().to_string(),
        )
        .map_err(|e| {
            warn!(
                "Failed to check if session exists for user {}: {}",
                user.username, e
            );
            PAASServerError::SessionError(Box::new(e))
        })?;

    if !session_valid {
        warn!(
            "{} tried to rekey to an invalid decryption context: {:?}",
            user.username, request.session_to
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    let rekey_info = pep_system.rekey_info(Some(&request.session_from), Some(&request.session_to));

    let msg_out = pep_system.rekey(&request.encrypted_data, &rekey_info);

    info!("{} rekeyed data", user.username,);

    Ok(HttpResponse::Ok().json(RekeyResponse {
        encrypted_data: msg_out,
    }))
}
pub async fn rekey_batch() -> impl Responder {
    HttpResponse::NotImplemented().body("Not implemented")
}
pub async fn transcrypt(
    item: web::Json<TranscryptionRequest>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_storage = session_storage.get_ref();

    let request = item.into_inner();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "{} tried, but was not allowed to transcrypt from {:?} to {:?}",
            user.username, request.domain_from, request.domain_to
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.0.clone(),
            to: request.domain_to.0.clone(),
        });
    }
    let session_valid = session_storage
        .session_exists(
            user.username.to_string(),
            request.session_to.clone().to_string(),
        )
        .map_err(|e| {
            warn!(
                "Failed to check if session exists for user {}: {}",
                user.username, e
            );
            PAASServerError::SessionError(Box::new(e))
        })?;

    if !session_valid {
        warn!(
            "{} tried to transcrypt to an invalid decryption context: {:?}",
            user.username, request.session_to
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    let pseudonymization_info = pep_system.pseudonymization_info(
        &request.domain_from,
        &request.domain_to,
        Some(&request.session_from),
        Some(&request.session_to),
    );

    let mut rng = rand::thread_rng();
    let msg_out = pep_system.transcrypt_batch(
        &mut request.encrypted.into_boxed_slice(),
        &pseudonymization_info,
        &mut rng,
    );

    info!(
        "{:?} transcrypted from {:?} to {:?}",
        user.username, request.domain_from.0, request.domain_to.0
    );

    Ok(HttpResponse::Ok().json(TranscryptionResponse {
        encrypted: Vec::from(msg_out),
    }))
}
