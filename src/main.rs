mod application {
    pub mod sessions;
    pub mod status;
    pub mod transcrypt;
}
mod access_rules;
mod auth_middleware;
mod pep_crypto;
mod session_storage;

use crate::access_rules::AccessRules;
use crate::application::sessions::{end_session, get_all_sessions, get_sessions, start_session};
use crate::application::status::status;
use crate::application::transcrypt::{pseudonymize, pseudonymize_batch, rekey};
use crate::auth_middleware::JWTAuthMiddleware;
use crate::session_storage::{RedisSessionStorage, SessionStorage};
use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use std::env;
use log::{info};
use env_logger;

const ACCESS_RULES_FILE_PATH: &str = "resources/access_rules.yml";
const JWT_PUBLIC_KEY_FILE_PATH: &str = "resources/public.pem";
const PEP_CRYPTO_SERVER_CONFIG_FILE_PATH: &str = "resources/server_config.yml";
const SERVER_LISTEN_ADDRESS: &str = "0.0.0.0:8080";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info,actix_web=warn,actix_server=warn")).init();

    info!("Loading access rules from {ACCESS_RULES_FILE_PATH}");
    let access_rules = AccessRules::load(ACCESS_RULES_FILE_PATH);
    info!("Loading JWT authentication middleware using public key from {JWT_PUBLIC_KEY_FILE_PATH}");
    let auth_middleware = JWTAuthMiddleware::new(JWT_PUBLIC_KEY_FILE_PATH);

    let session_storage: Box<dyn SessionStorage>;
    if env::var("REDIS_URL").is_err() {
        info!("Using in-memory session storage");
        session_storage = Box::new(session_storage::InMemorySessionStorage::new());
    } else {
        info!("Connecting to Redis session storage using Redis URL: {}", env::var("REDIS_URL").unwrap());
        session_storage= Box::new(
            RedisSessionStorage::new(env::var("REDIS_URL").unwrap())
                .expect("Failed to connect to Redis"),
        );
    }
    info!("Creating PEP crypto system from {PEP_CRYPTO_SERVER_CONFIG_FILE_PATH}");
    let pep_system = pep_crypto::create_pep_crypto_system(PEP_CRYPTO_SERVER_CONFIG_FILE_PATH);

    info!("Starting PaaS HTTP service on {SERVER_LISTEN_ADDRESS}");
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .wrap(Logger::default())
            .route("/status", web::get().to(status))
            .service(
                web::scope("")
                    .app_data(web::Data::new(access_rules.clone()))
                    .app_data(web::Data::new(session_storage.clone()))
                    .app_data(web::Data::new(pep_system.clone()))
                    .wrap(auth_middleware.clone())
                    .service(
                        web::scope("sessions")
                            .route("/get", web::get().to(get_all_sessions))
                            .route("/get/{username}", web::get().to(get_sessions))
                            .route("/start", web::post().to(start_session))
                            .route("/end", web::post().to(end_session)),
                    )
                    .service(
                        web::scope("")
                            .route("/pseudonymize", web::post().to(pseudonymize))
                            .route("/pseudonymize_batch", web::post().to(pseudonymize_batch))
                            .route("/rekey", web::post().to(rekey)),
                    ),
            )
    })
    .bind(SERVER_LISTEN_ADDRESS)?
    .run()
    .await
}
