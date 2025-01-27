use actix_web::{HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::env;

pub type SystemId = String;

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusResponse {
    pub system_id: SystemId,
    pub timestamp: String,
}

pub async fn status() -> impl Responder {
    let system_id = env::var("PAAS_SYSTEM_ID").unwrap();

    HttpResponse::Ok().json(StatusResponse {
        system_id,
        timestamp: chrono::offset::Local::now().to_string(),
    })
}
