use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use log::info;
use paas_server::access_rules::*;
use paas_server::application::sessions::*;
use paas_server::application::status::*;
use paas_server::application::transcrypt::*;
use paas_server::auth_middleware::*;
use paas_server::pep_crypto::*;
use paas_server::session_storage::*;
use std::env;

const ACCESS_RULES_FILE_PATH: &str = "resources/access_rules.yml";
const JWT_PUBLIC_KEY_FILE_PATH: &str = "resources/public.pem";
const PEP_CRYPTO_SERVER_CONFIG_FILE_PATH: &str = "resources/server_config.yml";
const SERVER_LISTEN_ADDRESS: &str = "0.0.0.0:8080";

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,actix_web=warn,actix_server=warn"),
    )
    .init();

    info!("Loading access rules from {ACCESS_RULES_FILE_PATH}");
    let access_rules = AccessRules::load(ACCESS_RULES_FILE_PATH);
    info!("Loading JWT authentication middleware using public key from {JWT_PUBLIC_KEY_FILE_PATH}");
    let auth_middleware = JWTAuthMiddleware::new(JWT_PUBLIC_KEY_FILE_PATH);

    let session_storage: Box<dyn SessionStorage> = if env::var("REDIS_URL").is_err() {
        info!("Using in-memory session storage");
        Box::new(InMemorySessionStorage::new())
    } else {
        let redis_url = env::var("REDIS_URL").unwrap();
        info!(
            "Connecting to Redis session storage using Redis URL: {}",
            redis_url
        );
        Box::new(RedisSessionStorage::new(redis_url).expect("Failed to connect to Redis"))
    };
    info!("Creating PEP crypto system from {PEP_CRYPTO_SERVER_CONFIG_FILE_PATH}");
    let pep_system = create_pep_crypto_system(PEP_CRYPTO_SERVER_CONFIG_FILE_PATH);

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
