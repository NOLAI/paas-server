use crate::auth::core::AuthInfo;
use crate::errors::PAASServerError;
use crate::session_storage::SessionStorage;
use actix_web::web::Data;
use actix_web::{web, HttpResponse};
use libpep::factors::EncryptionContext;
use libpep::transcryptor::DistributedTranscryptor;
use log::{info, warn};
use paas_api::sessions::{EndSessionRequest, SessionResponse, StartSessionResponse};

pub async fn start_session(
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<DistributedTranscryptor>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_id = session_storage
        .start_session(user.username.to_string())
        .map_err(|e| {
            warn!(
                "Storage error while starting session for user {}: {}",
                user.username, e
            );
            PAASServerError::SessionError(Box::new(e))
        })?;

    let ec_context = EncryptionContext::from(&session_id.clone());

    let session_key_shares = pep_system.session_key_shares(&ec_context);

    Ok(HttpResponse::Ok().json(StartSessionResponse {
        session_id: ec_context,
        session_key_shares,
    }))
}

pub async fn end_session(
    item: web::Json<EndSessionRequest>,
    session_storage: Data<Box<dyn SessionStorage>>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_id = item.session_id.clone();
    let EncryptionContext::Specific(session_id_str) = &item.session_id else {
        return Err(PAASServerError::InvalidSessionFormat(
            "Expected Specific context".to_string(),
        ));
    };
    let username_in_session =
        session_id_str
            .split('_')
            .next()
            .ok_or(PAASServerError::InvalidSessionFormat(
                session_id_str.clone(),
            ))?;

    if user.username.as_str() != username_in_session {
        warn!(
            "Unauthorized session access attempt: User {} tried to end session {:?} owned by {}",
            user.username, session_id, username_in_session
        );
        return Err(PAASServerError::UnauthorizedSession);
    }

    info!("{} ended session {:?}", user.username, session_id);

    session_storage
        .end_session(user.username.to_string(), session_id_str.clone())
        .map_err(|e| {
            warn!(
                "Storage error while ending session {:?} for user {}: {}",
                session_id, user.username, e
            );
            PAASServerError::SessionError(Box::new(e))
        })?;

    Ok(HttpResponse::Ok().json(()))
}

pub async fn get_sessions(
    session_storage: Data<Box<dyn SessionStorage>>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let sessions = session_storage
        .get_sessions_for_user(user.username.to_string())
        .map_err(|e| {
            warn!(
                "Failed to retrieve sessions for user {}: {}",
                user.username, e
            );
            PAASServerError::SessionError(Box::new(e))
        })?;

    Ok(HttpResponse::Ok().json(SessionResponse { sessions }))
}
