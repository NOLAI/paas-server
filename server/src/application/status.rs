use actix_web::{HttpResponse, Responder};
use paas_common::status::StatusResponse;
use std::env;

pub async fn status() -> impl Responder {
    let system_id = env::var("PAAS_SYSTEM_ID").unwrap();

    HttpResponse::Ok().json(StatusResponse {
        system_id,
        timestamp: chrono::offset::Local::now().to_string(),
    })
}
