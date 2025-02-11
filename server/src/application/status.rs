use actix_web::{HttpResponse, Responder};
use chrono::Utc;
use paas_api::status::{StatusResponse, VersionInfo};
use std::env;

pub async fn status() -> impl Responder {
    let system_id = env::var("PAAS_SYSTEM_ID").unwrap();

    HttpResponse::Ok().json(StatusResponse {
        system_id,
        timestamp: Utc::now(),
        version_info: VersionInfo::default(),
    })
}
