use crate::access_rules::AccessRules;
use crate::auth::core::AuthInfo;
use crate::errors::PAASServerError;
use crate::session_storage::SessionStorage;
use actix_web::web::Data;
use actix_web::{web, HttpResponse};
use libpep::data::traits::{HasStructure, Pseudonymizable, Rekeyable, Transcryptable};
use libpep::factors::{AttributeRekeyInfo, EncryptionContext, PseudonymRekeyInfo};
use libpep::transcryptor::DistributedTranscryptor;
use log::{info, warn};
use paas_api::transcrypt::{
    PseudonymizationBatchRequest, PseudonymizationBatchResponse, PseudonymizationRequest,
    PseudonymizationResponse, RekeyBatchRequest, RekeyBatchResponse, RekeyRequest, RekeyResponse,
    TranscryptionBatchRequest, TranscryptionBatchResponse, TranscryptionRequest,
    TranscryptionResponse,
};
use serde::Serialize;

pub async fn pseudonymize<T>(
    item: web::Json<PseudonymizationRequest<T>>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Pseudonymizable + Serialize,
{
    let session_storage = session_storage.get_ref();
    let request = item.into_inner();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "{} tried, but was not allowed to pseudonymize from {:?} to {:?}",
            user.username, request.domain_from, request.domain_to
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from,
            to: request.domain_to,
        });
    }
    let EncryptionContext::Specific(session_to_str) = &request.session_to else {
        return Err(PAASServerError::InvalidSession(
            "Expected Specific context".to_string(),
        ));
    };
    let session_valid = session_storage
        .session_exists(user.username.to_string(), session_to_str.clone())
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
        &request.session_from,
        &request.session_to,
    );

    let result = pep_system.pseudonymize(&request.encrypted, &pseudonymization_info);

    info!(
        "{:?} pseudonymized from {:?} to {:?}",
        user.username, request.domain_from, request.domain_to
    );

    Ok(HttpResponse::Ok().json(PseudonymizationResponse { result }))
}

pub async fn pseudonymize_batch<T>(
    item: web::Json<PseudonymizationBatchRequest<T>>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Pseudonymizable + Serialize + Clone + HasStructure,
{
    let session_storage = session_storage.get_ref();
    let mut request = item.into_inner();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "{} tried, but was not allowed to pseudonymize from {:?} to {:?}",
            user.username, request.domain_from, request.domain_to
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.clone(),
            to: request.domain_to.clone(),
        });
    }

    let EncryptionContext::Specific(session_to_str) = &request.session_to else {
        return Err(PAASServerError::InvalidSession(
            "Expected Specific context".to_string(),
        ));
    };
    let session_valid = session_storage
        .session_exists(user.username.to_string(), session_to_str.clone())
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
        &request.session_from,
        &request.session_to,
    );

    let mut rng = rand::rng();

    let msg_out =
        pep_system.pseudonymize_batch(&mut request.encrypted, &pseudonymization_info, &mut rng)?;

    info!(
        "{} batch-pseudonymized {} pseudonyms from {:?} to {:?}",
        user.username,
        request.encrypted.len(),
        request.domain_from,
        request.domain_to
    );

    Ok(HttpResponse::Ok().json(PseudonymizationBatchResponse {
        result: Vec::from(msg_out),
    }))
}

fn validate_rekey_request(
    session_to: &EncryptionContext,
    user: &AuthInfo,
    session_storage: &dyn SessionStorage,
) -> Result<(), PAASServerError> {
    let EncryptionContext::Specific(session_to_str) = session_to else {
        return Err(PAASServerError::InvalidSession(
            "Expected Specific context".to_string(),
        ));
    };
    let session_valid = session_storage
        .session_exists(user.username.to_string(), session_to_str.clone())
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
            user.username, session_to
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }
    Ok(())
}

pub async fn rekey_attribute<T>(
    item: web::Json<RekeyRequest<T>>,
    _access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Rekeyable<RekeyInfo = AttributeRekeyInfo> + Serialize,
{
    let session_storage = session_storage.get_ref();
    let request = item.into_inner();
    validate_rekey_request(&request.session_to, &user, session_storage.as_ref())?;

    let rekey_info = pep_system.attribute_rekey_info(&request.session_from, &request.session_to);
    let result = pep_system.rekey(&request.encrypted, &rekey_info);

    info!("{} rekeyed data", user.username);

    Ok(HttpResponse::Ok().json(RekeyResponse { result }))
}

pub async fn rekey_psuedonym<T>(
    item: web::Json<RekeyRequest<T>>,
    _access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Rekeyable<RekeyInfo = PseudonymRekeyInfo> + Serialize,
{
    let session_storage = session_storage.get_ref();
    let request = item.into_inner();
    validate_rekey_request(&request.session_to, &user, session_storage.as_ref())?;

    let rekey_info = pep_system.pseudonym_rekey_info(&request.session_from, &request.session_to);
    let result = pep_system.rekey(&request.encrypted, &rekey_info);

    info!("{} rekeyed data", user.username);

    Ok(HttpResponse::Ok().json(RekeyResponse { result }))
}

pub async fn rekey_batch_attribute<T>(
    item: web::Json<RekeyBatchRequest<T>>,
    _access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Rekeyable<RekeyInfo = AttributeRekeyInfo>
        + Serialize
        + Clone
        + HasStructure,
{
    let session_storage = session_storage.get_ref();
    let mut request = item.into_inner();

    validate_rekey_request(&request.session_to, &user, session_storage.as_ref())?;

    let rekey_info = pep_system.attribute_rekey_info(&request.session_from, &request.session_to);

    let mut rng = rand::rng();

    let msg_out = pep_system.rekey_batch(&mut request.encrypted, &rekey_info, &mut rng)?;

    info!(
        "{} batch-rekeyed {} attributes",
        user.username,
        msg_out.len()
    );

    Ok(HttpResponse::Ok().json(RekeyBatchResponse {
        result: msg_out.to_vec(),
    }))
}

pub async fn rekey_batch_psuedonym<T>(
    item: web::Json<RekeyBatchRequest<T>>,
    _access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Rekeyable<RekeyInfo = PseudonymRekeyInfo>
        + Serialize
        + Clone
        + HasStructure,
{
    let session_storage = session_storage.get_ref();
    let mut request = item.into_inner();

    validate_rekey_request(&request.session_to, &user, session_storage.as_ref())?;

    let rekey_info = pep_system.pseudonym_rekey_info(&request.session_from, &request.session_to);

    let mut rng = rand::rng();

    let msg_out = pep_system.rekey_batch(&mut request.encrypted, &rekey_info, &mut rng)?;

    info!(
        "{} batch-rekeyed {} attributes",
        user.username,
        msg_out.len()
    );

    Ok(HttpResponse::Ok().json(RekeyBatchResponse {
        result: msg_out.to_vec(),
    }))
}

pub async fn transcrypt<T>(
    item: web::Json<TranscryptionRequest<T>>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Transcryptable + Serialize,
{
    let session_storage = session_storage.get_ref();
    let request = item.into_inner();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "{} tried, but was not allowed to transcrypt from {:?} to {:?}",
            user.username, request.domain_from, request.domain_to
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.clone(),
            to: request.domain_to.clone(),
        });
    }
    let EncryptionContext::Specific(session_to_str) = &request.session_to else {
        return Err(PAASServerError::InvalidSession(
            "Expected Specific context".to_string(),
        ));
    };
    let session_valid = session_storage
        .session_exists(user.username.to_string(), session_to_str.clone())
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

    let transcryption_info = pep_system.transcryption_info(
        &request.domain_from,
        &request.domain_to,
        &request.session_from,
        &request.session_to,
    );

    let result = pep_system.transcrypt(&request.encrypted, &transcryption_info);

    info!(
        "{:?} transcrypted from {:?} to {:?}",
        user.username, request.domain_from, request.domain_to
    );

    Ok(HttpResponse::Ok().json(TranscryptionResponse { result }))
}

pub async fn transcrypt_batch<T>(
    item: web::Json<TranscryptionBatchRequest<T>>,
    access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Transcryptable + Serialize + HasStructure + Clone,
{
    let session_storage = session_storage.get_ref();
    let mut request = item.into_inner();

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "{} tried, but was not allowed to transcrypt from {:?} to {:?}",
            user.username, request.domain_from, request.domain_to
        );
        return Err(PAASServerError::AccessDenied {
            from: request.domain_from.clone(),
            to: request.domain_to.clone(),
        });
    }
    let EncryptionContext::Specific(session_to_str) = &request.session_to else {
        return Err(PAASServerError::InvalidSession(
            "Expected Specific context".to_string(),
        ));
    };
    let session_valid = session_storage
        .session_exists(user.username.to_string(), session_to_str.clone())
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

    let transcryption_info = pep_system.transcryption_info(
        &request.domain_from,
        &request.domain_to,
        &request.session_from,
        &request.session_to,
    );

    let mut rng = rand::rng();

    let result =
        pep_system.transcrypt_batch(&mut request.encrypted, &transcryption_info, &mut rng)?;

    info!(
        "{} batch-transcrypted {} items from {:?} to {:?}",
        user.username,
        result.len(),
        request.domain_from,
        request.domain_to
    );

    Ok(HttpResponse::Ok().json(TranscryptionBatchResponse {
        result: result.to_vec(),
    }))
}
