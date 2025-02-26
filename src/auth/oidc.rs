use crate::auth::generic::{AuthInfo, TokenValidator};
use crate::auth::jwt::Claims;
use actix_web::error::ErrorUnauthorized;
use actix_web::Error;
use jwks_client_rs::{source::WebSource, JwksClient, JwksClientError};
use reqwest::Url;
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct OIDCValidator {
    jwks_client: Arc<JwksClient<WebSource>>,
    audiences: Vec<String>,
    issuer: String,
    supported_algorithms: Vec<String>,
    userinfo_endpoint: Option<String>,
}

pub struct OIDCValidatorBuilder {
    issuer_url: Option<String>,
    audiences: Vec<String>,
    timeout: Duration,
    auto_discover_audiences: bool,
    preferred_algorithms: Option<Vec<String>>,
}

impl OIDCValidatorBuilder {
    /// Create a new OIDC validator builder with default values
    pub fn new() -> Self {
        Self {
            issuer_url: None,
            audiences: Vec::new(),
            timeout: Duration::from_secs(10),
            auto_discover_audiences: false,
            preferred_algorithms: None,
        }
    }

    /// Set the issuer URL for OIDC discovery
    pub fn with_issuer(mut self, issuer_url: impl Into<String>) -> Self {
        self.issuer_url = Some(issuer_url.into());
        self
    }

    /// Add an audience that the JWT must be intended for
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences.push(audience.into());
        self
    }

    /// Add multiple audiences that the JWT may be intended for
    pub fn with_audiences(
        mut self,
        audiences: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.audiences
            .extend(audiences.into_iter().map(|a| a.into()));
        self
    }

    /// Set whether to automatically discover audiences from the OIDC provider
    pub fn with_auto_discover_audiences(mut self, discover: bool) -> Self {
        self.auto_discover_audiences = discover;
        self
    }

    /// Set preferred signing algorithms in order of preference
    pub fn with_preferred_algorithms(mut self, algorithms: Vec<String>) -> Self {
        self.preferred_algorithms = Some(algorithms);
        self
    }

    /// Set the timeout for OIDC discovery and JWKS requests
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Build the OIDCValidator instance
    pub async fn build(self) -> Result<OIDCValidator, Error> {
        let issuer_url = self
            .issuer_url
            .ok_or_else(|| ErrorUnauthorized("OIDC issuer URL is required"))?;

        let client = reqwest::Client::new();
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );

        let metadata = client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| {
                eprintln!("Failed to discover OIDC provider: {}", e);
                ErrorUnauthorized(format!("Failed to discover OIDC provider: {}", e))
            })?
            .json::<Value>()
            .await
            .map_err(|e| ErrorUnauthorized(format!("Invalid OIDC discovery response: {}", e)))?;

        // Extract JWKS URI from metadata
        let jwks_uri = metadata["jwks_uri"]
            .as_str()
            .ok_or_else(|| ErrorUnauthorized("Missing jwks_uri in OIDC discovery"))?;

        // Parse and validate the JWKS URL
        let jwks_url = Url::parse(jwks_uri)
            .map_err(|e| ErrorUnauthorized(format!("Invalid JWKS URI: {}", e)))?;

        // Get supported algorithms from metadata
        let provider_algorithms = metadata["id_token_signing_alg_values_supported"]
            .as_array()
            .map(|algs| {
                algs.iter()
                    .filter_map(|alg| alg.as_str().map(String::from))
                    .collect::<Vec<String>>()
            })
            .unwrap_or_else(|| vec!["RS256".to_string()]); // Default to RS256 if not specified

        // Determine which algorithms to use (preferred or discovered)
        let algorithms_to_use = if let Some(preferred) = self.preferred_algorithms {
            // Filter preferred algorithms to only include those supported by the provider
            preferred
                .into_iter()
                .filter(|alg| provider_algorithms.contains(alg))
                .collect::<Vec<String>>()
        } else {
            // Use provider's algorithms
            provider_algorithms.clone()
        };

        // If no algorithms match, use RS256 as a fallback
        let final_algorithms = if algorithms_to_use.is_empty() {
            vec!["RS256".to_string()]
        } else {
            algorithms_to_use
        };

        // Log the algorithms being used
        println!(
            "Using OIDC token signing algorithms: {:?}",
            final_algorithms
        );

        // Configure the WebSource
        let source = WebSource::builder()
            .with_timeout(self.timeout)
            .with_connect_timeout(self.timeout)
            .build(jwks_url)
            .map_err(|e| ErrorUnauthorized(format!("Failed to create WebSource: {}", e)))?;

        // Build the JWKS client
        // NOTE: jwks_client_rs doesn't have a direct way to specify algorithms,
        // it will accept keys for various algorithms from the JWKS endpoint
        let jwks_client = JwksClient::builder().build(source);

        // Collect audiences (manually specified + auto-discovered if enabled)
        let mut audiences = self.audiences;

        // Auto-discover audiences if enabled
        if self.auto_discover_audiences {
            // Look for client_id, client_id_issued_at, and registered client entries
            // This is based on the OAuth 2.0 Dynamic Client Registration protocol

            // Try to get client IDs from registered clients
            if let Some(clients) = metadata.get("registered_clients").and_then(Value::as_array) {
                for client in clients {
                    if let Some(client_id) = client.get("client_id").and_then(Value::as_str) {
                        audiences.push(client_id.to_string());
                    }
                }
            }

            // Check for client ID in the metadata itself (some providers include it)
            if let Some(client_id) = metadata.get("client_id").and_then(Value::as_str) {
                audiences.push(client_id.to_string());
            }

            // Some providers list client IDs in an array
            if let Some(client_ids) = metadata.get("client_ids").and_then(Value::as_array) {
                for client_id in client_ids {
                    if let Some(id) = client_id.as_str() {
                        audiences.push(id.to_string());
                    }
                }
            }

            // If we didn't find any audiences and auto-discovery is enabled, try to use the issuer as a fallback
            if audiences.is_empty() {
                // Get the issuer from the metadata
                if let Some(metadata_issuer) = metadata.get("issuer").and_then(Value::as_str) {
                    audiences.push(metadata_issuer.to_string());
                } else {
                    // Use the provided issuer URL as a last resort
                    audiences.push(issuer_url.clone());
                }
            }
        }

        // If no audiences were found or provided, add a warning log
        if audiences.is_empty() {
            eprintln!("Warning: No audiences specified or discovered for OIDC validator. This may cause validation failures.");
        }

        // Get userinfo endpoint for additional user info if needed
        let userinfo_endpoint = metadata["userinfo_endpoint"].as_str().map(String::from);

        Ok(OIDCValidator {
            jwks_client: Arc::new(jwks_client),
            audiences,
            issuer: issuer_url,
            supported_algorithms: final_algorithms,
            userinfo_endpoint,
        })
    }
}

impl OIDCValidator {
    /// Create a new builder for configuring the OIDC validator
    pub fn builder() -> OIDCValidatorBuilder {
        OIDCValidatorBuilder::new()
    }

    /// Create a simple OIDC validator with minimal configuration (for backward compatibility)
    pub async fn new(
        issuer_url: &str,
        audiences: Vec<&str>,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let mut builder = Self::builder()
            .with_issuer(issuer_url)
            .with_timeout(timeout);

        for audience in audiences {
            builder = builder.with_audience(audience);
        }

        builder.build().await
    }

    /// Create an OIDC validator with auto-discovered audiences
    pub async fn new_with_discovery(issuer_url: &str, timeout: Duration) -> Result<Self, Error> {
        Self::builder()
            .with_issuer(issuer_url)
            .with_timeout(timeout)
            .with_auto_discover_audiences(true)
            .build()
            .await
    }

    /// Get the currently configured audiences
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// Get the issuer URL
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Get the supported algorithms
    pub fn supported_algorithms(&self) -> &[String] {
        &self.supported_algorithms
    }

    /// Get the userinfo endpoint if available
    pub fn userinfo_endpoint(&self) -> Option<&str> {
        self.userinfo_endpoint.as_deref()
    }

    /// Fetch additional user information from the userinfo endpoint
    pub async fn fetch_userinfo(&self, access_token: &str) -> Result<Value, Error> {
        let userinfo_url = self
            .userinfo_endpoint
            .as_ref()
            .ok_or_else(|| ErrorUnauthorized("Userinfo endpoint not available"))?;

        let client = reqwest::Client::new();
        let response = client
            .get(userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ErrorUnauthorized(format!("Failed to fetch userinfo: {}", e)))?;

        if !response.status().is_success() {
            return Err(ErrorUnauthorized(format!(
                "Userinfo request failed with status: {}",
                response.status()
            )));
        }

        response
            .json::<Value>()
            .await
            .map_err(|e| ErrorUnauthorized(format!("Failed to parse userinfo response: {}", e)))
    }

    /// Check if a specific algorithm is supported
    pub fn supports_algorithm(&self, algorithm: &str) -> bool {
        self.supported_algorithms.contains(&algorithm.to_string())
    }
}

impl TokenValidator for OIDCValidator {
    fn validate_token<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AuthInfo, Error>> + Send + 'a>> {
        let token = token.to_string();
        let audiences = self.audiences.clone();
        let jwks_client = self.jwks_client.clone();

        Box::pin(async move {
            // Decode and validate the token
            // JwksClient internally fetches the JWK based on the token's header
            // and validates using the appropriate algorithm
            let token_data: Result<Claims, JwksClientError> =
                jwks_client.decode::<Claims>(&token, &audiences).await;

            match token_data {
                Ok(claims) => {
                    // Convert claims to AuthInfo
                    Ok(AuthInfo {
                        username: claims.sub,
                        groups: claims.groups,
                    })
                }
                Err(e) => {
                    // Return specific error based on validation failure
                    Err(ErrorUnauthorized(format!("Invalid OIDC token: {}", e)))
                }
            }
        })
    }
}
