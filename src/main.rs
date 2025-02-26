use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{web, App, Error, HttpServer};
use log::info;
use paas_server::access_rules::*;
use paas_server::application::sessions::*;
use paas_server::application::status::*;
use paas_server::application::transcrypt::*;
use paas_server::auth::generic::{AuthInfo, Authentication, TokenValidator};
use paas_server::auth::jwt::JWTValidator;
use paas_server::auth::oidc::OIDCValidator;
use paas_server::auth::token::SimpleTokenValidator;
use paas_server::pep_crypto::*;
use paas_server::session_storage::*;
use std::env;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[allow(clippy::upper_case_acronyms)]
enum AuthType {
    SimpleToken,
    JWT,
    OIDC,
}

struct ServerConfig {
    access_rules_path: String,

    // Common auth config
    auth_type: AuthType,

    // Simple token auth config
    token_users_path: Option<String>,

    // JWT auth config
    jwt_key_path: Option<String>,
    jwt_audience: Option<String>,

    // OIDC auth config
    oidc_provider_url: Option<String>,
    oidc_audiences: Option<Vec<String>>,
    oidc_discovery_timeout: Duration,

    pep_crypto_server_config_path: String,
    public_paas_config_path: String,
    server_listen_address: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            access_rules_path: "resources/access_rules.yml".to_string(),

            // Default to SimpleToken auth
            auth_type: AuthType::SimpleToken,

            // Simple token config
            token_users_path: Some("resources/token_users.yml".to_string()),

            // JWT config
            jwt_key_path: Some("resources/public.pem".to_string()),
            jwt_audience: None,

            // OIDC config
            oidc_provider_url: None,
            oidc_audiences: None,
            oidc_discovery_timeout: Duration::from_secs(10),

            pep_crypto_server_config_path: "resources/server_config.yml".to_string(),
            public_paas_config_path: "resources/paas_config.json".to_string(),
            server_listen_address: "0.0.0.0:8080".to_string(),
        }
    }
}

impl ServerConfig {
    fn from_env() -> Self {
        // Determine auth type from environment
        let auth_type = match env::var("AUTH_TYPE")
            .unwrap_or_else(|_| "token".to_string())
            .to_lowercase()
            .as_str()
        {
            "jwt" => AuthType::JWT,
            "oidc" => AuthType::OIDC,
            _ => AuthType::SimpleToken, // Default to token auth
        };

        Self {
            access_rules_path: env::var("ACCESS_RULES_PATH")
                .unwrap_or_else(|_| Self::default().access_rules_path),

            auth_type,

            // Simple token config
            token_users_path: env::var("TOKEN_USERS_PATH").ok(),

            // JWT config
            jwt_key_path: env::var("JWT_KEY_PATH").ok(),
            jwt_audience: env::var("JWT_AUDIENCE").ok(),

            // OIDC config
            oidc_provider_url: env::var("OIDC_PROVIDER_URL").ok(),
            oidc_audiences: env::var("OIDC_AUDIENCES")
                .ok()
                .map(|v| parse_comma_separated(Some(v), vec![])),
            oidc_discovery_timeout: parse_duration(
                env::var("OIDC_DISCOVERY_TIMEOUT").ok(),
                Self::default().oidc_discovery_timeout,
            ),

            pep_crypto_server_config_path: env::var("PEP_CRYPTO_SERVER_CONFIG_PATH")
                .unwrap_or_else(|_| Self::default().pep_crypto_server_config_path),
            public_paas_config_path: env::var("PUBLIC_PAAS_CONFIG_PATH")
                .unwrap_or_else(|_| Self::default().public_paas_config_path),
            server_listen_address: env::var("SERVER_LISTEN_ADDRESS")
                .unwrap_or_else(|_| Self::default().server_listen_address),
        }
    }
}

fn parse_comma_separated(env_var: Option<String>, default: Vec<String>) -> Vec<String> {
    match env_var {
        Some(value) if !value.trim().is_empty() => value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => default,
    }
}

fn parse_duration(env_var: Option<String>, default: Duration) -> Duration {
    match env_var {
        Some(value) => match value.parse::<u64>() {
            Ok(seconds) => Duration::from_secs(seconds),
            Err(_) => {
                eprintln!("Invalid duration value '{}', using default", value);
                default
            }
        },
        None => default,
    }
}

#[derive(Clone)]
pub enum ValidatorEnum {
    SimpleToken(SimpleTokenValidator),
    JWT(JWTValidator),
    OIDC(OIDCValidator),
}

impl TokenValidator for ValidatorEnum {
    fn validate_token<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AuthInfo, Error>> + Send + 'a>> {
        match self {
            Self::SimpleToken(v) => v.validate_token(token),
            Self::JWT(v) => v.validate_token(token),
            Self::OIDC(v) => v.validate_token(token),
        }
    }
}

// Now update your build_auth function to return the combined type
async fn build_auth(server_config: &ServerConfig) -> Authentication<ValidatorEnum> {
    match server_config.auth_type {
        AuthType::SimpleToken => {
            let token_users_path = server_config
                .token_users_path
                .as_deref()
                .expect("TOKEN_USERS_PATH must be set when AUTH_TYPE=token");
            info!(
                "Using simple token authentication with users from {}",
                token_users_path
            );
            let token_validator = SimpleTokenValidator::load(token_users_path);
            Authentication::new(ValidatorEnum::SimpleToken(token_validator))
        }
        AuthType::JWT => {
            let jwt_key_path = server_config
                .jwt_key_path
                .as_deref()
                .expect("JWT_KEY_PATH must be set when AUTH_TYPE=jwt");
            let audience = server_config
                .jwt_audience
                .as_deref()
                .expect("JWT_AUDIENCE must be set when AUTH_TYPE=jwt");

            info!("Using JWT authentication with key from {}", jwt_key_path);
            let jwt_validator =
                JWTValidator::new(jwt_key_path, audience).expect("Failed to create JWT validator");

            Authentication::new(ValidatorEnum::JWT(jwt_validator))
        }
        AuthType::OIDC => {
            let provider_url = server_config
                .oidc_provider_url
                .as_deref()
                .expect("OIDC_PROVIDER_URL must be set when AUTH_TYPE=oidc");
            let audiences: Vec<_> = server_config
                .oidc_audiences
                .as_ref()
                .map(|a| a.iter().map(|s| s.as_str()).collect())
                .unwrap_or_default();

            info!(
                "Using OIDC authentication with provider {} and audiences {:?}",
                provider_url, audiences
            );

            // Create the validator asynchronously
            let oidc_validator = if audiences.is_empty() {
                info!("No OIDC audiences specified, using auto-discovery");
                OIDCValidator::new_with_discovery(
                    provider_url,
                    server_config.oidc_discovery_timeout,
                )
                .await
                .expect("Failed to create OIDC validator")
            } else {
                OIDCValidator::new(
                    provider_url,
                    audiences,
                    server_config.oidc_discovery_timeout,
                )
                .await
                .expect("Failed to create OIDC validator")
            };

            Authentication::new(ValidatorEnum::OIDC(oidc_validator))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,actix_web=warn,actix_server=warn"),
    )
    .init();

    let server_config = ServerConfig::from_env();

    info!(
        "Loading access rules from {}",
        server_config.access_rules_path
    );
    let access_rules = AccessRules::load(&server_config.access_rules_path);

    let auth = build_auth(&server_config).await;

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

    info!(
        "Starting PaaS HTTP service on {}",
        server_config.server_listen_address
    );
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .wrap(Logger::default())
            .service(
                web::scope(paas_api::paths::API_BASE)
                    .app_data(web::Data::new(paas_system_id.clone()))
                    .route(paas_api::paths::STATUS, web::get().to(status))
                    .service(
                        web::scope("")
                            .app_data(web::Data::new(access_rules.clone()))
                            .app_data(web::Data::new(session_storage.clone()))
                            .app_data(web::Data::new(pep_system.clone()))
                            .app_data(web::Data::new(paas_config.clone()))
                            .wrap(auth.clone())
                            .route(paas_api::paths::CONFIG, web::get().to(config))
                            .route(paas_api::paths::SESSIONS_GET, web::get().to(get_sessions))
                            .route(
                                paas_api::paths::SESSIONS_START,
                                web::post().to(start_session),
                            )
                            .route(paas_api::paths::SESSIONS_END, web::post().to(end_session))
                            .route(paas_api::paths::PSEUDONYMIZE, web::post().to(pseudonymize))
                            .route(
                                paas_api::paths::PSEUDONYMIZE_BATCH,
                                web::post().to(pseudonymize_batch),
                            )
                            .route(paas_api::paths::REKEY, web::post().to(rekey))
                            .route(paas_api::paths::REKEY_BATCH, web::post().to(rekey_batch))
                            .route(paas_api::paths::TRANSCRYPT, web::post().to(transcrypt)),
                    ),
            )
    })
    .bind(&server_config.server_listen_address)?
    .run()
    .await
}
