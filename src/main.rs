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
use log::{info, warn};
use env_logger;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info,actix_web=warn,actix_server=warn")).init();

    let access_rules = AccessRules::load("resources/access_rules.yml");
    let auth_middleware = JWTAuthMiddleware::new("resources/public.pem");
    let session_storage: Box<dyn SessionStorage> = Box::new(
        RedisSessionStorage::new(env::var("REDIS_URL").unwrap())
            .expect("Failed to connect to Redis"),
    );
    let pep_system = pep_crypto::create_pep_crypto_system("resources/server_config.yml");

    info!("Starting HTTP service");
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
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
