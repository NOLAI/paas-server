use actix_web::web::Data;
use actix_web::{HttpResponse, Responder};
use chrono::Utc;
use paas_api::config::PAASConfig;
use paas_api::status::{StatusResponse, SystemId, VersionInfo};
use std::fs;

pub async fn status(paas_system_id: Data<SystemId>) -> impl Responder {
    HttpResponse::Ok().json(StatusResponse {
        system_id: paas_system_id.to_string(),
        timestamp: Utc::now(),
        version_info: VersionInfo::default(),
    })
}

pub fn load_paas_config(config_file: &str) -> PAASConfig {
    let file_content =
        fs::read_to_string(config_file).expect("Failed to read public PAAS config file");
    serde_json::from_str(&file_content).expect("Failed to parse public PAAS config file")
}

pub async fn config(paas_config: Data<PAASConfig>) -> impl Responder {
    HttpResponse::Ok().json(paas_config)
}
