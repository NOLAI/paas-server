use crate::auth::core::AuthInfo;
use crate::errors::PAASServerError;
use crate::session_storage::SessionStorage;
use actix_web::web::Data;
use actix_web::{web, HttpResponse};
use libpep::distributed::systems::PEPSystem;
use libpep::high_level::contexts::EncryptionContext;
use log::{info, warn};
use paas_api::sessions::{EndSessionRequest, SessionResponse, StartSessionResponse};

pub async fn start_session(
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_id = session_storage
        .start_session(user.sub.to_string())
        .map_err(|e| {
            warn!(
                "Storage error while starting session: {} error={}",
                *user, e
            );
            PAASServerError::SessionError(Box::new(e))
        })?;

    let ec_context = EncryptionContext::from(&session_id.clone());

    info!("Started session: session={:?} {}", session_id, *user);

    let session_key_shares = pep_system.session_key_shares(&ec_context.clone());

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

    let sub_in_session = session_id
        .split('_')
        .next()
        .ok_or(PAASServerError::InvalidSessionFormat(session_id.clone().0))?;

    if user.sub.as_str() != sub_in_session {
        warn!(
            "Unauthorized session access attempt: session={:?} {} owner={}",
            session_id, *user, sub_in_session
        );
        return Err(PAASServerError::UnauthorizedSession);
    }

    info!("Ended session: session={:?} {}", session_id, *user);

    session_storage
        .end_session(user.sub.to_string(), session_id.to_string())
        .map_err(|e| {
            warn!(
                "Storage error while ending session: session={:?} {} error={}",
                session_id, *user, e
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
        .get_sessions_for_user(user.sub.to_string())
        .map_err(|e| {
            warn!("Failed to retrieve sessions: {} error={}", *user, e);
            PAASServerError::SessionError(Box::new(e))
        })?;

    Ok(HttpResponse::Ok().json(SessionResponse { sessions }))
}
