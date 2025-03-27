use crate::auth::jwt::JWTAuthConfig;
use crate::auth::oidc::OIDCAuthConfig;
use crate::auth::token::SimpleTokenAuthConfig;
use std::env;
use std::time::Duration;

#[allow(clippy::upper_case_acronyms)]
pub enum AuthTypeConfig {
    SimpleToken,
    JWT,
    OIDC,
}
pub struct ServerConfig {
    pub access_rules_path: String,
    pub auth_type: AuthTypeConfig,
    pub simple_token_config: Option<SimpleTokenAuthConfig>,
    pub jwt_config: Option<JWTAuthConfig>,
    pub oidc_config: Option<OIDCAuthConfig>,
    pub pep_crypto_server_config_path: String,
    pub public_paas_config_path: String,
    pub server_listen_address: String,
    pub request_timeout: Duration,
    pub redis_url: Option<String>,
    pub workers: Option<usize>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            access_rules_path: "resources/access_rules.yml".to_string(),
            auth_type: AuthTypeConfig::SimpleToken,
            simple_token_config: Some(SimpleTokenAuthConfig {
                token_users_path: "resources/token_users.yml".to_string(),
            }),
            jwt_config: Some(JWTAuthConfig {
                jwt_key_path: "resources/public.pem".to_string(),
                jwt_audience: String::new(),
            }),
            oidc_config: None,
            pep_crypto_server_config_path: "resources/server_config.yml".to_string(),
            public_paas_config_path: "resources/paas_config.json".to_string(),
            server_listen_address: "0.0.0.0:8080".to_string(),
            request_timeout: Duration::from_secs(60),
            redis_url: None,
            workers: None,
        }
    }
}

impl ServerConfig {
    pub fn from_env() -> Self {
        // Determine auth type from environment
        let auth_type = match env::var("AUTH_TYPE")
            .unwrap_or_else(|_| "token".to_string())
            .to_lowercase()
            .as_str()
        {
            "jwt" => AuthTypeConfig::JWT,
            "oidc" => AuthTypeConfig::OIDC,
            _ => AuthTypeConfig::SimpleToken, // Default to token auth
        };

        // Create appropriate auth config based on auth type
        let simple_token_config = match auth_type {
            AuthTypeConfig::SimpleToken => Some(SimpleTokenAuthConfig {
                token_users_path: env::var("TOKEN_USERS_PATH")
                    .unwrap_or_else(|_| "resources/token_users.yml".to_string()),
            }),
            _ => None,
        };

        let jwt_config = match auth_type {
            AuthTypeConfig::JWT => Some(JWTAuthConfig {
                jwt_key_path: env::var("JWT_KEY_PATH")
                    .expect("JWT_KEY_PATH must be set when AUTH_TYPE=jwt"),
                jwt_audience: env::var("JWT_AUDIENCE")
                    .expect("JWT_AUDIENCE must be set when AUTH_TYPE=jwt"),
            }),
            _ => None,
        };

        let oidc_config = match auth_type {
            AuthTypeConfig::OIDC => {
                let audiences = env::var("OIDC_AUDIENCES")
                    .map(|v| parse_comma_separated(v, vec![]))
                    .expect("OIDC_AUDIENCES must be set when AUTH_TYPE=oidc");

                if audiences.is_empty() {
                    panic!("OIDC_AUDIENCES cannot be empty when AUTH_TYPE=oidc");
                }

                Some(OIDCAuthConfig {
                    provider_url: env::var("OIDC_PROVIDER_URL")
                        .expect("OIDC_PROVIDER_URL must be set when AUTH_TYPE=oidc"),
                    audiences,
                    discovery_timeout: parse_duration(
                        env::var("OIDC_DISCOVERY_TIMEOUT").ok(),
                        Duration::from_secs(10),
                    ),
                })
            }
            _ => None,
        };

        Self {
            access_rules_path: env::var("ACCESS_RULES_PATH")
                .unwrap_or_else(|_| "resources/access_rules.yml".to_string()),
            auth_type,
            simple_token_config,
            jwt_config,
            oidc_config,
            pep_crypto_server_config_path: env::var("PEP_CRYPTO_SERVER_CONFIG_PATH")
                .unwrap_or_else(|_| "resources/server_config.yml".to_string()),
            public_paas_config_path: env::var("PUBLIC_PAAS_CONFIG_PATH")
                .unwrap_or_else(|_| "resources/paas_config.json".to_string()),
            server_listen_address: env::var("SERVER_LISTEN_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            request_timeout: parse_duration(
                env::var("REQUEST_TIMEOUT").ok(),
                Duration::from_secs(60),
            ),
            redis_url: env::var("REDIS_URL").ok(),
            workers: env::var("WORKERS")
                .ok()
                .and_then(|w| w.parse::<usize>().ok()),
        }
    }
}

fn parse_comma_separated(value: String, default: Vec<String>) -> Vec<String> {
    if value.trim().is_empty() {
        default
    } else {
        value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
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
