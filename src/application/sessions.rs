use crate::auth::core::AuthInfo;
use crate::errors::PAASServerError;
use crate::session_storage::SessionStorage;
use actix_web::web::Data;
use actix_web::{web, HttpResponse};
use libpep::distributed::systems::PEPSystem;
use libpep::high_level::contexts::EncryptionContext;
use paas_api::sessions::{EndSessionRequest, SessionResponse, StartSessionResponse};
use tracing::{debug, error, info, instrument, warn, Span};

#[instrument(skip(session_storage, pep_system), fields(user = %user.username))]
pub async fn start_session(
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    debug!("Starting new session");

    let session_id = match session_storage.start_session(user.username.to_string()) {
        Ok(id) => id,
        Err(e) => {
            error!(error = %format!("{:?}", e), "Failed to start session");
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    let ec_context = EncryptionContext::from(&session_id.clone());
    Span::current().record("session_id", ec_context.to_string());

    debug!("Session started successfully, generating key share");

    let key_share = pep_system.session_key_share(&ec_context.clone());

    info!("Session started with key share generated");

    Ok(HttpResponse::Ok().json(StartSessionResponse {
        session_id: ec_context,
        key_share,
    }))
}

#[instrument(skip(item, session_storage), fields(user = %user.username, session_id = %item.session_id.0))]
pub async fn end_session(
    item: web::Json<EndSessionRequest>,
    session_storage: Data<Box<dyn SessionStorage>>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    let session_id = item.session_id.clone();
    debug!("Processing end session request");

    let username_in_session = match session_id.split('_').next() {
        Some(username) => username,
        None => {
            error!("Invalid session format");
            return Err(PAASServerError::InvalidSessionFormat(session_id.clone().0));
        }
    };

    if user.username.as_str() != username_in_session {
        warn!(
            session_owner = %username_in_session,
            "Unauthorized session access attempt"
        );
        return Err(PAASServerError::UnauthorizedSession);
    }

    debug!("Authorization validated, ending session");

    match session_storage.end_session(user.username.to_string(), session_id.to_string()) {
        Ok(_) => {
            info!("Session ended successfully");
            Ok(HttpResponse::Ok().json(()))
        }
        Err(e) => {
            error!(error = %format!("{:?}", e), "Failed to end session");
            Err(PAASServerError::SessionError(Box::new(e)))
        }
    }
}

#[instrument(skip(session_storage), fields(user = %user.username))]
pub async fn get_sessions(
    session_storage: Data<Box<dyn SessionStorage>>,
    user: web::ReqData<AuthInfo>,
) -> Result<HttpResponse, PAASServerError> {
    debug!("Retrieving sessions for user");

    let sessions = match session_storage.get_sessions_for_user(user.username.to_string()) {
        Ok(sessions) => sessions,
        Err(e) => {
            error!(error = %format!("{:?}", e), "Failed to retrieve sessions");
            return Err(PAASServerError::SessionError(Box::new(e)));
        }
    };

    info!(count = sessions.len(), "Successfully retrieved sessions");

    Ok(HttpResponse::Ok().json(SessionResponse { sessions }))
}
