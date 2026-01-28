use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use libpep::client::prelude::{EncryptedAttribute, EncryptedPseudonym};
use libpep::data::json::EncryptedPEPJSONValue;
use libpep::data::long::{LongEncryptedAttribute, LongEncryptedPseudonym};
use libpep::data::records::{EncryptedRecord, LongEncryptedRecord};
use log::info;
use paas_server::access_rules::*;
use paas_server::application::sessions::*;
use paas_server::application::status::{config, health, load_paas_config, status};
use paas_server::application::transcrypt::*;
use paas_server::auth::core::Authentication;
use paas_server::auth::jwt::JWTValidator;
use paas_server::auth::oidc::OIDCValidator;
use paas_server::auth::token::SimpleTokenValidator;
use paas_server::auth::AuthType;
use paas_server::config::{AuthTypeConfig, ServerConfig};
use paas_server::pep_crypto::*;
use paas_server::session_storage::*;
use std::env;

async fn build_auth(server_config: &ServerConfig) -> Authentication<AuthType> {
    match server_config.auth_type {
        AuthTypeConfig::SimpleToken => {
            let config = server_config
                .simple_token_config
                .as_ref()
                .expect("SimpleTokenAuthConfig should be present when auth_type is SimpleToken");

            info!(
                "Using simple token authentication with users from {}",
                config.token_users_path
            );
            let token_validator = SimpleTokenValidator::load(&config.token_users_path);
            Authentication::new(AuthType::SimpleToken(token_validator))
        }
        AuthTypeConfig::JWT => {
            let config = server_config
                .jwt_config
                .as_ref()
                .expect("JWTAuthConfig should be present when auth_type is JWT");

            info!(
                "Using JWT authentication with key from {}",
                config.jwt_key_path
            );
            let jwt_validator = JWTValidator::new(&config.jwt_key_path, &config.jwt_audience)
                .expect("Failed to create JWT validator");

            Authentication::new(AuthType::Jwt(jwt_validator))
        }
        AuthTypeConfig::OIDC => {
            let config = server_config
                .oidc_config
                .as_ref()
                .expect("OIDCAuthConfig should be present when auth_type is OIDC");

            info!(
                "Using OIDC authentication with provider {}",
                config.provider_url
            );
            info!("Using OIDC audiences {:?}", config.audiences);

            let audiences: Vec<_> = config.audiences.iter().map(|s| s.as_str()).collect();

            let oidc_validator =
                OIDCValidator::new(&config.provider_url, audiences, config.discovery_timeout)
                    .await
                    .expect("Failed to create OIDC validator");

            Authentication::new(AuthType::Oidc(oidc_validator))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let server_config = ServerConfig::from_env();

    info!(
        "Loading access rules from {}",
        server_config.access_rules_path
    );
    let access_rules = AccessRules::load(&server_config.access_rules_path);

    let auth = build_auth(&server_config).await;

    let session_storage: Box<dyn SessionStorage> = if let Some(redis_url) = &server_config.redis_url
    {
        let options = server_config
            .redis_options
            .expect("RedisOptions should be present when using Redis session storage");
        info!(
            "Connecting to Redis session storage using Redis URL: {}",
            redis_url
        );
        Box::new(
            RedisSessionStorage::new(
                redis_url.as_str(),
                server_config.pep_session_lifetime,
                server_config.pep_session_length,
                options,
            )
            .expect("Failed to connect to Redis"),
        )
    } else {
        if server_config.workers.unwrap_or(1) > 1 {
            info!("Using in-memory session storage with shared state for multiple workers");
        } else {
            info!("Using in-memory session storage");
        }
        Box::new(InMemorySessionStorage::new(
            server_config.pep_session_lifetime,
            server_config.pep_session_length,
        ))
    };

    info!(
        "Creating PEP crypto system from {}",
        server_config.pep_crypto_server_config_path
    );
    let pep_system = create_pep_crypto_system(&server_config.pep_crypto_server_config_path);

    info!(
        "Loading public PAAS config from {}",
        server_config.public_paas_config_path
    );
    let paas_system_id = env::var("PAAS_SYSTEM_ID").unwrap();
    let paas_config = load_paas_config(&server_config.public_paas_config_path);

    // Validate all transcryptor URLs use HTTPS
    for transcryptor in &paas_config.transcryptors {
        if transcryptor.url.scheme() != "https" {
            panic!(
                "Transcryptor {} URL must use HTTPS protocol, got: {}",
                transcryptor.system_id,
                transcryptor.url.scheme()
            );
        }
    }

    info!(
        "Starting PaaS HTTP service on {}",
        server_config.server_listen_address
    );

    let mut server = HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .wrap(Logger::default())
            .service(
                web::scope(paas_api::paths::API_BASE)
                    .app_data(web::Data::new(paas_system_id.clone()))
                    .app_data(web::Data::new(session_storage.clone()))
                    .route("/health", web::get().to(health))
                    .route(paas_api::paths::STATUS, web::get().to(status))
                    .service(
                        web::scope("")
                            .app_data(web::Data::new(access_rules.clone()))
                            .app_data(web::Data::new(pep_system.clone()))
                            .app_data(web::Data::new(paas_config.clone()))
                            .wrap(auth.clone())
                            .wrap(Cors::permissive())
                            .route(paas_api::paths::CONFIG, web::get().to(config))
                            .route(paas_api::paths::SESSIONS_GET, web::get().to(get_sessions))
                            .route(
                                paas_api::paths::SESSIONS_START,
                                web::post().to(start_session),
                            )
                            .route(paas_api::paths::SESSIONS_END, web::post().to(end_session))
                            // Pseudonymization routes
                            .route(
                                paas_api::paths::pseudonymize_path::<EncryptedPseudonym>().as_str(),
                                web::post().to(pseudonymize::<EncryptedPseudonym>),
                            )
                            .route(
                                paas_api::paths::pseudonymize_path::<LongEncryptedPseudonym>()
                                    .as_str(),
                                web::post().to(pseudonymize::<LongEncryptedPseudonym>),
                            )
                            // Batch pseudonymization routes
                            .route(
                                paas_api::paths::pseudonymize_batch_path::<EncryptedPseudonym>()
                                    .as_str(),
                                web::post().to(pseudonymize_batch::<EncryptedPseudonym>),
                            )
                            .route(
                                paas_api::paths::pseudonymize_batch_path::<LongEncryptedPseudonym>(
                                )
                                .as_str(),
                                web::post().to(pseudonymize_batch::<LongEncryptedPseudonym>),
                            )
                            // Rekeying routes
                            .route(
                                paas_api::paths::rekey_path::<EncryptedAttribute>().as_str(),
                                web::post().to(rekey_attribute::<EncryptedAttribute>),
                            )
                            .route(
                                paas_api::paths::rekey_path::<LongEncryptedAttribute>().as_str(),
                                web::post().to(rekey_attribute::<LongEncryptedAttribute>),
                            )
                            .route(
                                paas_api::paths::rekey_path::<EncryptedPseudonym>().as_str(),
                                web::post().to(rekey_psuedonym::<EncryptedPseudonym>),
                            )
                            .route(
                                paas_api::paths::rekey_path::<LongEncryptedPseudonym>().as_str(),
                                web::post().to(rekey_psuedonym::<LongEncryptedPseudonym>),
                            )
                            // Batch rekeying routes
                            .route(
                                paas_api::paths::rekey_batch_path::<EncryptedAttribute>().as_str(),
                                web::post().to(rekey_batch_attribute::<EncryptedAttribute>),
                            )
                            .route(
                                paas_api::paths::rekey_batch_path::<LongEncryptedAttribute>()
                                    .as_str(),
                                web::post().to(rekey_batch_attribute::<LongEncryptedAttribute>),
                            )
                            .route(
                                paas_api::paths::rekey_batch_path::<EncryptedPseudonym>().as_str(),
                                web::post().to(rekey_batch_psuedonym::<EncryptedPseudonym>),
                            )
                            .route(
                                paas_api::paths::rekey_batch_path::<LongEncryptedPseudonym>()
                                    .as_str(),
                                web::post().to(rekey_batch_psuedonym::<LongEncryptedPseudonym>),
                            )
                            // Transcryption routes
                            .route(
                                paas_api::paths::transcrypt_path::<EncryptedPseudonym>().as_str(),
                                web::post().to(transcrypt::<EncryptedPseudonym>),
                            )
                            .route(
                                paas_api::paths::transcrypt_path::<LongEncryptedPseudonym>()
                                    .as_str(),
                                web::post().to(transcrypt::<LongEncryptedPseudonym>),
                            )
                            .route(
                                paas_api::paths::transcrypt_path::<LongEncryptedAttribute>()
                                    .as_str(),
                                web::post().to(transcrypt::<LongEncryptedAttribute>),
                            )
                            .route(
                                paas_api::paths::transcrypt_path::<LongEncryptedAttribute>()
                                    .as_str(),
                                web::post().to(transcrypt::<LongEncryptedAttribute>),
                            )
                            .route(
                                paas_api::paths::transcrypt_path::<EncryptedRecord>().as_str(),
                                web::post().to(transcrypt::<EncryptedRecord>),
                            )
                            .route(
                                paas_api::paths::transcrypt_path::<LongEncryptedRecord>().as_str(),
                                web::post().to(transcrypt::<LongEncryptedRecord>),
                            )
                            .route(
                                paas_api::paths::transcrypt_path::<EncryptedPEPJSONValue>()
                                    .as_str(),
                                web::post().to(transcrypt::<EncryptedPEPJSONValue>),
                            )
                            // Batch transcryption routes
                            .route(
                                paas_api::paths::transcrypt_batch_path::<EncryptedPseudonym>()
                                    .as_str(),
                                web::post().to(transcrypt_batch::<EncryptedPseudonym>),
                            )
                            .route(
                                paas_api::paths::transcrypt_batch_path::<LongEncryptedPseudonym>()
                                    .as_str(),
                                web::post().to(transcrypt_batch::<LongEncryptedPseudonym>),
                            )
                            .route(
                                paas_api::paths::transcrypt_batch_path::<EncryptedAttribute>()
                                    .as_str(),
                                web::post().to(transcrypt_batch::<EncryptedAttribute>),
                            )
                            .route(
                                paas_api::paths::transcrypt_batch_path::<LongEncryptedAttribute>()
                                    .as_str(),
                                web::post().to(transcrypt_batch::<LongEncryptedAttribute>),
                            )
                            .route(
                                paas_api::paths::transcrypt_batch_path::<EncryptedRecord>()
                                    .as_str(),
                                web::post().to(transcrypt_batch::<EncryptedRecord>),
                            )
                            .route(
                                paas_api::paths::transcrypt_batch_path::<LongEncryptedRecord>()
                                    .as_str(),
                                web::post().to(transcrypt_batch::<LongEncryptedRecord>),
                            )
                            .route(
                                paas_api::paths::transcrypt_batch_path::<EncryptedPEPJSONValue>()
                                    .as_str(),
                                web::post().to(transcrypt_batch::<EncryptedPEPJSONValue>),
                            ),
                    ),
            )
    })
    .client_request_timeout(server_config.request_timeout);

    if let Some(workers) = server_config.workers {
        info!("Using {} workers for the server", workers);
        server = server.workers(workers);
    }

    server
        .bind(&server_config.server_listen_address)?
        .run()
        .await
}
