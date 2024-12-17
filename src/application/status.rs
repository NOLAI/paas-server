use std::env;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use crate::access_rules::AuthenticatedUser;

#[derive(Serialize, Deserialize)]
pub struct StatusResponse {
    system_id: String,
    timestamp: String,
    whoami: String,
}

pub async fn status(
    req: HttpRequest,
) -> impl Responder {
    let system_id = env::var("HOSTNAME").unwrap();
    let user = req
        .extensions()
        .get::<AuthenticatedUser>()
        .unwrap()
        .clone();

    HttpResponse::Ok().json(StatusResponse {
        system_id,
        timestamp: chrono::offset::Local::now().to_string(),
        whoami: user.username.to_string(),
    })
}