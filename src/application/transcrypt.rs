use crate::access_rules::AccessRules;
use crate::auth::core::AuthInfo;
use crate::errors::PAASServerError;
use crate::session_storage::SessionStorage;
use actix_web::web::Data;
use actix_web::{web, HttpResponse, Responder};
use libpep::distributed::systems::PEPSystem;
use paas_api::transcrypt::{
    PseudonymizationBatchRequest, PseudonymizationBatchResponse, PseudonymizationRequest,
    PseudonymizationResponse, RekeyRequest, RekeyResponse, TranscryptionRequest,
    TranscryptionResponse,
};
use tracing::{debug, error, info, instrument, warn};

#[instrument(
    skip(access_rules, session_storage, pep_system),
    fields(
        user = %user.username,
        domain_from = %item.domain_from.0,
        domain_to = %item.domain_to.0,
        session_from = %item.session_from.0,
        session_to = %item.session_to.0
    )
)]
pub async fn pseudonymize(
    item: web::Json<PseudonymizationRequest>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_storage = session_storage.get_ref();
    let request = item.into_inner();

    debug!("Processing pseudonymization request");

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: not allowed to pseudonymize from {:?} to {:?}",
            request.domain_from, request.domain_to
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.0.clone(),
            to: request.domain_to.0.clone(),
        });
    }

    let session_valid = match session_storage.session_exists(
        user.username.to_string(),
        request.session_to.clone().to_string(),
    ) {
        Ok(valid) => valid,
        Err(e) => {
            error!(error = %format!("{:?}", e), "Failed to check if session exists");
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    if !session_valid {
        warn!(
            session = %request.session_to.0,
            "Attempted to use invalid decryption context"
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    debug!("Session validation successful, performing pseudonymization");

    let pseudonymization_info = pep_system.pseudonymization_info(
        &request.domain_from,
        &request.domain_to,
        Some(&request.session_from),
        Some(&request.session_to),
    );

    let msg_out = pep_system.pseudonymize(&request.encrypted_pseudonym, &pseudonymization_info);

    info!("Pseudonymization successful");

    Ok(HttpResponse::Ok().json(PseudonymizationResponse {
        encrypted_pseudonym: msg_out,
    }))
}

#[instrument(
    skip(item, access_rules, session_storage, pep_system),
    fields(
        user = %user.username,
        domain_from = %item.domain_from.0,
        domain_to = %item.domain_to.0,
        session_from = %item.session_from.0,
        session_to = %item.session_to.0,
        batch_size = item.encrypted_pseudonyms.len()
    )
)]
pub async fn pseudonymize_batch(
    item: web::Json<PseudonymizationBatchRequest>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_storage = session_storage.get_ref();

    let request = item.into_inner();

    debug!("Processing batch pseudonymization request");

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: not allowed to pseudonymize from {} to {}",
            request.domain_from.0, request.domain_to.0
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.0.clone(),
            to: request.domain_to.0.clone(),
        });
    }

    let session_valid = match session_storage.session_exists(
        user.username.to_string(),
        request.session_to.clone().to_string(),
    ) {
        Ok(valid) => valid,
        Err(e) => {
            error!(error = %format!("{:?}", e), "Failed to check if session exists");
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    if !session_valid {
        warn!(
            session = %request.session_to.0,
            "Attempted to use invalid decryption context"
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    debug!("Session validation successful, performing batch pseudonymization");

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
        count = request.encrypted_pseudonyms.len(),
        "Batch pseudonymization successful"
    );

    Ok(HttpResponse::Ok().json(PseudonymizationBatchResponse {
        encrypted_pseudonyms: Vec::from(msg_out),
    }))
}

#[instrument(
    skip(item, _access_rules, session_storage, pep_system),
    fields(
        user = %user.username,
        session_from = %item.session_from.0,
        session_to = %item.session_to.0
    )
)]
pub async fn rekey(
    item: web::Json<RekeyRequest>,
    _access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_storage = session_storage.get_ref();
    debug!("Processing rekey request");

    let request = item.into_inner();

    // TODO: check access rules!

    let session_valid = match session_storage.session_exists(
        user.username.to_string(),
        request.session_to.clone().to_string(),
    ) {
        Ok(valid) => valid,
        Err(e) => {
            error!(error = %format!("{:?}", e), "Failed to check if session exists");
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    if !session_valid {
        warn!(
            session = %request.session_to.0,
            "Attempted to rekey to an invalid session"
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    debug!("Session validation successful, performing rekey operation");

    let rekey_info =
        pep_system.attribute_rekey_info(Some(&request.session_from), Some(&request.session_to));

    let msg_out = pep_system.rekey(&request.encrypted_attribute, &rekey_info);

    info!("Rekey operation successful");

    Ok(HttpResponse::Ok().json(RekeyResponse {
        encrypted_attribute: msg_out,
    }))
}

pub async fn rekey_batch() -> impl Responder {
    HttpResponse::NotImplemented().body("Not implemented")
}

#[instrument(
    skip(item, access_rules, session_storage, pep_system),
    fields(
        user = %user.username,
        domain_from = %item.domain_from.0,
        domain_to = %item.domain_to.0,
        session_from = %item.session_from.0,
        session_to = %item.session_to.0,
        entity_count = item.encrypted.len()
    )
)]
pub async fn transcrypt(
    item: web::Json<TranscryptionRequest>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_storage = session_storage.get_ref();
    debug!("Processing transcrypt request");

    let request = item.into_inner();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: not allowed to transcrypt from {:?} to {:?}",
            request.domain_from, request.domain_to
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.0.clone(),
            to: request.domain_to.0.clone(),
        });
    }

    let session_valid = match session_storage.session_exists(
        user.username.to_string(),
        request.session_to.clone().to_string(),
    ) {
        Ok(valid) => valid,
        Err(e) => {
            error!(error = %format!("{:?}", e), "Failed to check if session exists");
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    if !session_valid {
        warn!(
            session = %request.session_to.0,
            "Attempted to transcrypt with invalid session"
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    debug!("Session validation successful, performing transcryption");

    let batch_size = request.encrypted.len();

    let transcryption_info = pep_system.transcryption_info(
        &request.domain_from,
        &request.domain_to,
        Some(&request.session_from),
        Some(&request.session_to),
    );

    let mut rng = rand::thread_rng();
    let msg_out = pep_system.transcrypt_batch(
        &mut request.encrypted.into_boxed_slice(),
        &transcryption_info,
        &mut rng,
    );

    info!(entity_count = batch_size, "Transcryption successful");

    Ok(HttpResponse::Ok().json(TranscryptionResponse {
        encrypted: Vec::from(msg_out),
    }))
}
