use crate::access_rules::AuthenticatedUser;
use crate::session_storage::SessionStorage;
use actix_web::web::Data;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use libpep::distributed::key_blinding::SessionKeyShare;
use libpep::distributed::systems::PEPSystem;
use libpep::high_level::contexts::EncryptionContext;
use log::info;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct GetSessionsRequest {
    username: Option<EncryptionContext>,
}
#[derive(Serialize, Deserialize)]
pub struct GetSessionResponse {
    sessions: Vec<EncryptionContext>,
}

#[derive(Serialize, Deserialize)]
pub struct StartSessionResponse {
    session_id: String,
    key_share: SessionKeyShare,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EndSessionRequest {
    session_id: String,
}
pub async fn start_session(
    req: HttpRequest,
    session_storage: Data<Box<dyn SessionStorage>>,
    pep_system: Data<PEPSystem>,
) -> impl Responder {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .unwrap();
    let session_storage: &mut Box<dyn SessionStorage> = session_storage.get_ref();

    let session_id = session_storage
        .start_session(user.username.to_string())
        .unwrap();

    info!("{:?} started session {:?}", user.username, session_id);

    let key_share = pep_system.session_key_share(&EncryptionContext::from(&session_id.clone()));

    HttpResponse::Ok().json(StartSessionResponse {
        session_id,
        key_share,
    })
}

pub async fn end_session(
    item: web::Json<EndSessionRequest>,
    req: HttpRequest,
    session_storage: Data<Box<dyn SessionStorage>>,
) -> impl Responder {
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .cloned()
        .unwrap();
    let session_storage = session_storage.get_ref();

    let session_id = item.session_id.clone();
    let username_in_session = session_id.split('_').next().unwrap();
    if user.username.as_str() != username_in_session {
        return HttpResponse::Forbidden().body("Session not owned by user");
    }

    info!("{:?} ended session {:?}", user.username, session_id);

    session_storage
        .end_session(user.username.to_string(), session_id)
        .unwrap();

    HttpResponse::Ok().json({})
}

pub async fn get_sessions(
    path: web::Path<GetSessionsRequest>,
    session_storage: Data<Box<dyn SessionStorage>>,
) -> impl Responder {
    let session_storage = session_storage.get_ref();
    let sessions = session_storage
        .get_sessions_for_user(path.username.clone().unwrap().to_string())
        .unwrap();
    HttpResponse::Ok().json(GetSessionResponse { sessions })
}

pub async fn get_all_sessions(session_storage: Data<Box<dyn SessionStorage>>) -> impl Responder {
    let sessions = session_storage.get_ref().get_all_sessions().unwrap();
    HttpResponse::Ok().json(GetSessionResponse { sessions })
}
