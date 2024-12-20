use actix_web::{HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Serialize, Deserialize)]
pub struct StatusResponse {
    pub system_id: String,
    pub timestamp: String,
}

pub async fn status() -> impl Responder {
    let system_id = env::var("PAAS_SYSTEM_ID").unwrap();

    HttpResponse::Ok().json(StatusResponse {
        system_id,
        timestamp: chrono::offset::Local::now().to_string(),
    })
}
