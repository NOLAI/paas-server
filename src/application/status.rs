use actix_web::web::Data;
use actix_web::{HttpResponse, Responder};
use chrono::Utc;
use log::error;
use paas_api::config::PAASConfig;
use paas_api::status::{StatusResponse, SystemId, VersionInfo};
use serde::Serialize;
use std::fs;

use crate::session_storage::SessionStorage;

#[derive(Serialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub checks: HealthChecks,
}

#[derive(Serialize)]
pub struct HealthChecks {
    pub session_storage: CheckStatus,
}

#[derive(Serialize)]
pub struct CheckStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub async fn health(session_storage: Data<Box<dyn SessionStorage>>) -> impl Responder {
    let mut overall_healthy = true;

    // Check session storage connectivity
    let storage_check = match check_session_storage(session_storage.get_ref().as_ref()).await {
        Ok(_) => CheckStatus {
            status: "healthy".to_string(),
            message: None,
        },
        Err(e) => {
            overall_healthy = false;
            error!("Session storage health check failed: {:?}", e);
            CheckStatus {
                status: "unhealthy".to_string(),
                message: Some(format!("Session storage check failed: {:?}", e)),
            }
        }
    };

    let response = HealthCheckResponse {
        status: if overall_healthy {
            "healthy"
        } else {
            "unhealthy"
        }
        .to_string(),
        timestamp: Utc::now(),
        checks: HealthChecks {
            session_storage: storage_check,
        },
    };

    if overall_healthy {
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::ServiceUnavailable().json(response)
    }
}

async fn check_session_storage(storage: &dyn SessionStorage) -> Result<(), std::fmt::Error> {
    // Try to perform a lightweight operation to verify storage is accessible
    // For Redis: this will check connection pool health
    // For InMemory: this will verify the mutex isn't poisoned
    storage.get_all_sessions().map(|_| ())
}

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
    let config: PAASConfig =
        serde_json::from_str(&file_content).expect("Failed to parse public PAAS config file");

    config
}

pub async fn config(paas_config: Data<PAASConfig>) -> impl Responder {
    HttpResponse::Ok().json(paas_config)
}
