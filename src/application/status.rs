use actix_web::{HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Serialize, Deserialize)]
pub struct StatusResponse {
    system_id: String,
    timestamp: String,
}

pub async fn status() -> impl Responder {
    let system_id = env::var("HOSTNAME").unwrap();

    HttpResponse::Ok().json(StatusResponse {
        system_id,
        timestamp: chrono::offset::Local::now().to_string(),
    })
}
