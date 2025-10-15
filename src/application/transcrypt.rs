use crate::access_rules::AccessRules;
use crate::auth::core::AuthInfo;
use crate::errors::PAASServerError;
use crate::session_storage::SessionStorage;
use actix_web::web::Data;
use actix_web::{web, HttpResponse};
use libpep::distributed::systems::PEPSystem;
use log::{debug, error, info, warn};
use paas_api::transcrypt::{
    PseudonymizationBatchRequest, PseudonymizationBatchResponse, PseudonymizationRequest,
    PseudonymizationResponse, RekeyBatchRequest, RekeyBatchResponse, RekeyRequest,
    RekeyResponse, TranscryptionRequest, TranscryptionResponse,
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

    debug!(
        "Processing pseudonymization request: domain={}→{} session={}→{} {}",
        request.domain_from.0,
        request.domain_to.0,
        request.session_from.0,
        request.session_to.0,
        *user
    );

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: domain={}→{} {}",
            request.domain_from.0, request.domain_to.0, *user
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.0.clone(),
            to: request.domain_to.0.clone(),
        });
    }

    let session_valid = match session_storage
        .session_exists(user.sub.to_string(), request.session_to.clone().to_string())
    {
        Ok(valid) => valid,
        Err(e) => {
            error!(
                "Failed to check if session exists: session={} {}",
                request.session_to.0, *user
            );
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    if !session_valid {
        warn!(
            "Invalid session: session={} {}",
            request.session_to.0, *user
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
        "Pseudonymized: domain={}→{} session={}→{} {}",
        request.domain_from.0,
        request.domain_to.0,
        request.session_from.0,
        request.session_to.0,
        *user
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
    let batch_size = request.encrypted_pseudonyms.len();

    debug!(
        "Processing batch pseudonymization request: domain={}→{} session={}→{} count={} {}",
        request.domain_from.0,
        request.domain_to.0,
        request.session_from.0,
        request.session_to.0,
        batch_size,
        *user
    );

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: domain={}→{} {}",
            request.domain_from.0, request.domain_to.0, *user
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.0.clone(),
            to: request.domain_to.0.clone(),
        });
    }

    let session_valid = match session_storage
        .session_exists(user.sub.to_string(), request.session_to.clone().to_string())
    {
        Ok(valid) => valid,
        Err(e) => {
            error!(
                "Failed to check if session exists: session={} {}",
                request.session_to.0, *user
            );
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    if !session_valid {
        warn!(
            "Invalid session: session={} {}",
            request.session_to.0, *user
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
        "Pseudonymized batch: domain={}→{} session={}→{} count={} {}",
        request.domain_from.0,
        request.domain_to.0,
        request.session_from.0,
        request.session_to.0,
        batch_size,
        *user
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

    debug!(
        "Processing rekey request: session={}→{} {}",
        request.session_from.0, request.session_to.0, *user
    );

    // TODO: check access rules!

    let session_valid = match session_storage
        .session_exists(user.sub.to_string(), request.session_to.clone().to_string())
    {
        Ok(valid) => valid,
        Err(e) => {
            error!(
                "Failed to check if session exists: session={} {}",
                request.session_to.0, *user
            );
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    if !session_valid {
        warn!(
            "Invalid session: session={} {}",
            request.session_to.0, *user
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    let rekey_info =
        pep_system.attribute_rekey_info(Some(&request.session_from), Some(&request.session_to));

    let msg_out = pep_system.rekey(&request.encrypted_attribute, &rekey_info);

    info!(
        "Rekeyed: session={}→{} {}",
        request.session_from.0, request.session_to.0, *user
    );

    Ok(HttpResponse::Ok().json(RekeyResponse {
        encrypted_attribute: msg_out,
    }))
}

pub async fn rekey_batch(
    item: web::Json<RekeyBatchRequest>,
    _access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_storage = session_storage.get_ref();
    let request = item.into_inner();
    let batch_size = request.encrypted_attributes.len();

    debug!(
        "Processing batch rekey request: session={}→{} count={} {}",
        request.session_from.0, request.session_to.0, batch_size, *user
    );

    // TODO: check access rules!

    let session_valid = match session_storage
        .session_exists(user.sub.to_string(), request.session_to.clone().to_string())
    {
        Ok(valid) => valid,
        Err(e) => {
            error!(
                "Failed to check if session exists: session={} {}",
                request.session_to.0, *user
            );
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    if !session_valid {
        warn!(
            "Invalid session: session={} {}",
            request.session_to.0, *user
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    let rekey_info =
        pep_system.attribute_rekey_info(Some(&request.session_from), Some(&request.session_to));

    let mut encrypted_attributes = request.encrypted_attributes.clone();
    let mut rng = rand::thread_rng();
    let msg_out = pep_system.rekey_batch(&mut encrypted_attributes, &rekey_info, &mut rng);

    info!(
        "Rekeyed batch: session={}→{} count={} {}",
        request.session_from.0, request.session_to.0, batch_size, *user
    );

    Ok(HttpResponse::Ok().json(RekeyBatchResponse {
        encrypted_attributes: Vec::from(msg_out),
    }))
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
    let batch_size = request.encrypted.len();

    debug!(
        "Processing transcrypt request: domain={}→{} session={}→{} count={} {}",
        request.domain_from.0,
        request.domain_to.0,
        request.session_from.0,
        request.session_to.0,
        batch_size,
        *user
    );

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: domain={}→{} {}",
            request.domain_from.0, request.domain_to.0, *user
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.0.clone(),
            to: request.domain_to.0.clone(),
        });
    }

    let session_valid = match session_storage
        .session_exists(user.sub.to_string(), request.session_to.clone().to_string())
    {
        Ok(valid) => valid,
        Err(e) => {
            error!(
                "Failed to check if session exists: session={} {}",
                request.session_to.0, *user
            );
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    if !session_valid {
        warn!(
            "Invalid session: session={} {}",
            request.session_to.0, *user
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

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

    info!(
        "Transcrypted: domain={}→{} session={}→{} count={} {}",
        request.domain_from.0,
        request.domain_to.0,
        request.session_from.0,
        request.session_to.0,
        batch_size,
        *user
    );

    Ok(HttpResponse::Ok().json(TranscryptionResponse {
        encrypted: Vec::from(msg_out),
    }))
}
