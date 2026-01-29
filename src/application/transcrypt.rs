use crate::access_rules::AccessRules;
use crate::auth::core::AuthInfo;
use crate::errors::PAASServerError;
use crate::session_storage::SessionStorage;
use actix_web::web::Data;
use actix_web::{web, HttpResponse};
use libpep::data::traits::{HasStructure, Pseudonymizable, Rekeyable, Transcryptable};
use libpep::factors::{EncryptionContext, RekeyInfoProvider};
use libpep::transcryptor::{DistributedTranscryptor, Transcryptor};
use log::{debug, error, info, warn};
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

    debug!(
        "Processing pseudonymization request: domain={:?}→{:?} session={:?}→{:?} {}",
        request.domain_from, request.domain_to, request.session_from, request.session_to, *user
    );

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: domain={:?}→{:?} {:?}",
            request.domain_from, request.domain_to, *user
        );
        return Err(PAASServerError::AccessDenied {
            from: format!("{:?}", request.domain_from.clone()),
            to: format!("{:?}", request.domain_to.clone()),
        });
    }

    let session_valid =
        match session_storage.session_exists(user.sub.to_string(), request.session_to.clone()) {
            Ok(valid) => valid,
            Err(e) => {
                error!(
                    "Failed to check if session exists: session={:?} {}",
                    request.session_to, *user
                );
                return Err(PAASServerError::SessionError(Box::new(e)));
            }
        };

    if !session_valid {
        warn!(
            "Invalid session: session={:?} {}",
            request.session_to, *user
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
        "Pseudonymized: domain={:?}→{:?} session={:?}→{:?} {}",
        request.domain_from, request.domain_to, request.session_from, request.session_to, *user
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
    let request = item.into_inner();
    let batch_size = request.encrypted.len();

    debug!(
        "Processing batch pseudonymization request: domain={:?}→{:?} session={:?}→{:?} count={} {}",
        request.domain_from,
        request.domain_to,
        request.session_from,
        request.session_to,
        batch_size,
        *user
    );

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: domain={:?}→{:?} {}",
            request.domain_from, request.domain_to, *user
        );
        return Err(PAASServerError::AccessDenied {
            from: format!("{:?}", request.domain_from.clone()),
            to: format!("{:?}", request.domain_to.clone()),
        });
    }

    let session_valid =
        match session_storage.session_exists(user.sub.to_string(), request.session_to.clone()) {
            Ok(valid) => valid,
            Err(e) => {
                error!(
                    "Failed to check if session exists: session={:?} {}",
                    request.session_to, *user
                );
                return Err(PAASServerError::SessionError(Box::new(e)));
            }
        };

    if !session_valid {
        warn!(
            "Invalid session: session={:?} {}",
            request.session_to, *user
        );
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }

    let mut encrypted_pseudonyms = request.encrypted.clone();
    let mut rng = rand::rng();

    let pseudonymization_info = pep_system.pseudonymization_info(
        &request.domain_from,
        &request.domain_to,
        &request.session_from,
        &request.session_to,
    );

    let msg_out = pep_system.pseudonymize_batch(
        &mut encrypted_pseudonyms,
        &pseudonymization_info,
        &mut rng,
    )?;

    info!(
        "Pseudonymized batch: domain={:?}→{:?} session={:?}→{:?} count={} {}",
        request.domain_from,
        request.domain_to,
        request.session_from,
        request.session_to,
        batch_size,
        *user
    );

    Ok(HttpResponse::Ok().json(PseudonymizationBatchResponse {
        result: Vec::from(msg_out),
    }))
}

#[allow(unreachable_code)]
fn validate_rekey_request(
    _session_to: &EncryptionContext,
    _user: &AuthInfo,
    _session_storage: &dyn SessionStorage,
) -> Result<(), PAASServerError> {
    // TODO: check access rules!
    return Err(PAASServerError::Unauthorized(
        "Rekeying is currently disabled pending access rule implementation".to_string(),
    ));

    let session_valid =
        match _session_storage.session_exists(_user.sub.to_string(), _session_to.clone()) {
            Ok(valid) => valid,
            Err(e) => {
                error!(
                    "Failed to check if session exists: session={:?} {}",
                    _session_to, *_user
                );
                return Err(PAASServerError::SessionError(Box::new(e)));
            }
        };

    if !session_valid {
        warn!("Invalid session: session={:?} {}", _session_to, *_user);
        return Err(PAASServerError::InvalidSession(
            "Target session not owned by user".to_string(),
        ));
    }
    Ok(())
}

pub async fn rekey<T>(
    item: web::Json<RekeyRequest<T>>,
    _access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Rekeyable + Serialize,
    Transcryptor: RekeyInfoProvider<<T as Rekeyable>::RekeyInfo>,
{
    let session_storage = session_storage.get_ref();
    let request = item.into_inner();

    debug!(
        "Processing rekey request: session={:?}→{:?} {}",
        request.session_from, request.session_to, *user
    );

    validate_rekey_request(&request.session_to, &user, session_storage.as_ref())?;

    let rekey_info = pep_system.rekey_info(&request.session_from, &request.session_to);

    let result = pep_system.rekey(&request.encrypted, &rekey_info);

    info!(
        "Rekeyed: session={:?}→{:?} {}",
        request.session_from, request.session_to, *user
    );

    Ok(HttpResponse::Ok().json(RekeyResponse { result }))
}

pub async fn rekey_batch<T>(
    item: web::Json<RekeyBatchRequest<T>>,
    _access_rules: Data<AccessRules>,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError>
where
    T: Rekeyable + Serialize + Clone + HasStructure,
    Transcryptor: RekeyInfoProvider<<T as Rekeyable>::RekeyInfo>,
    <T as Rekeyable>::RekeyInfo: Copy,
{
    let session_storage = session_storage.get_ref();
    let request = item.into_inner();
    let batch_size = request.encrypted.len();

    debug!(
        "Processing batch rekey request: session={:?}→{:?} count={} {}",
        request.session_from, request.session_to, batch_size, *user
    );
    validate_rekey_request(&request.session_to, &user, session_storage.as_ref())?;

    let rekey_info = pep_system.rekey_info(&request.session_from, &request.session_to);

    let mut encrypted = request.encrypted.clone();
    let mut rng = rand::rng();
    let msg_out = pep_system.rekey_batch(&mut encrypted, &rekey_info, &mut rng)?;

    info!(
        "Rekeyed batch: session={:?}→{:?} count={} {}",
        request.session_from, request.session_to, batch_size, *user
    );

    Ok(HttpResponse::Ok().json(RekeyBatchResponse {
        result: Vec::from(msg_out),
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

    debug!(
        "Processing transcrypt request: domain={:?}→{:?} session={:?}→{:?} {}",
        request.domain_from, request.domain_to, request.session_from, request.session_to, *user
    );

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: domain={:?}→{:?} {}",
            request.domain_from, request.domain_to, *user
        );
        return Err(PAASServerError::AccessDenied {
            from: format!("{:?}", request.domain_from.clone()),
            to: format!("{:?}", request.domain_to.clone()),
        });
    }

    let session_valid =
        match session_storage.session_exists(user.sub.to_string(), request.session_to.clone()) {
            Ok(valid) => valid,
            Err(e) => {
                error!(
                    "Failed to check if session exists: session={:?} {}",
                    request.session_to, *user
                );
                return Err(PAASServerError::SessionError(Box::new(e)));
            }
        };

    if !session_valid {
        warn!(
            "Invalid session: session={:?} {}",
            request.session_to, *user
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
        "Transcrypted: domain={:?}→{:?} session={:?}→{:?} {}",
        request.domain_from, request.domain_to, request.session_from, request.session_to, *user
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
    let request = item.into_inner();
    let batch_size = request.encrypted.len();

    debug!(
        "Processing transcrypt batch request: domain={:?}→{:?} session={:?}→{:?} count={} {}",
        request.domain_from,
        request.domain_to,
        request.session_from,
        request.session_to,
        batch_size,
        *user
    );

    if !access_rules.has_access(&user, &request.domain_from, &request.domain_to) {
        warn!(
            "Access denied: domain={:?}→{:?} {}",
            request.domain_from, request.domain_to, *user
        );
        return Err(PAASServerError::AccessDenied {
            from: format!("{:?}", request.domain_from.clone()),
            to: format!("{:?}", request.domain_to.clone()),
        });
    }

    let session_valid =
        match session_storage.session_exists(user.sub.to_string(), request.session_to.clone()) {
            Ok(valid) => valid,
            Err(e) => {
                error!(
                    "Failed to check if session exists: session={:?} {}",
                    request.session_to, *user
                );
                return Err(PAASServerError::SessionError(Box::new(e)));
            }
        };

    if !session_valid {
        warn!(
            "Invalid session: session={:?} {}",
            request.session_to, *user
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
    let msg_out = pep_system.transcrypt_batch(
        &mut request.encrypted.into_boxed_slice(),
        &transcryption_info,
        &mut rng,
    )?;

    info!(
        "Transcrypted: domain={:?}→{:?} session={:?}→{:?} count={} {}",
        request.domain_from,
        request.domain_to,
        request.session_from,
        request.session_to,
        batch_size,
        *user
    );

    Ok(HttpResponse::Ok().json(TranscryptionBatchResponse {
        result: Vec::from(msg_out),
    }))
}
