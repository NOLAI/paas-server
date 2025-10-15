use crate::auth::core::{AuthInfo, TokenValidator};
use actix_web::error::ErrorUnauthorized;
use actix_web::Error;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

pub struct JWTAuthConfig {
    pub jwt_key_path: String,
    pub jwt_audience: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    // Standard claims
    pub sub: String,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(default)]
    pub nbf: Option<u64>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<String>,

    // Custom claims
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Clone)]
pub struct JWTValidator {
    jwt_key: Arc<DecodingKey>,
    validation: Arc<Validation>,
}

#[derive(Default)]
pub struct JWTValidatorBuilder {
    jwt_key: Option<DecodingKey>,
    audiences: Vec<String>,
    issuer: Option<String>,
    algorithm: Algorithm,
    leeway: u64,
    validate_exp: bool,
    validate_nbf: bool,
    validate_aud: bool,
}

impl JWTValidatorBuilder {
    /// Create a new JWT validator builder with default values
    pub fn new() -> Self {
        Self {
            jwt_key: None,
            audiences: Vec::new(),
            issuer: None,
            algorithm: Algorithm::RS256,
            leeway: 0,
            validate_exp: true,
            validate_nbf: true,
            validate_aud: true,
        }
    }

    /// Set the JWT key using a PEM-formatted RSA public key from file
    pub fn with_rsa_pem_key_file<P: AsRef<Path>>(mut self, file_path: P) -> Result<Self, Error> {
        let key_content = fs::read_to_string(file_path)
            .map_err(|e| ErrorUnauthorized(format!("Failed to read JWT key file: {}", e)))?;

        self.jwt_key = Some(
            DecodingKey::from_rsa_pem(key_content.as_bytes())
                .map_err(|e| ErrorUnauthorized(format!("Invalid RSA public key: {}", e)))?,
        );

        Ok(self)
    }

    /// Set the JWT key using a PEM-formatted RSA public key from string
    pub fn with_rsa_pem_key(mut self, key_content: &str) -> Result<Self, Error> {
        self.jwt_key = Some(
            DecodingKey::from_rsa_pem(key_content.as_bytes())
                .map_err(|e| ErrorUnauthorized(format!("Invalid RSA public key: {}", e)))?,
        );

        Ok(self)
    }

    /// Set the JWT key directly
    pub fn with_key(mut self, key: DecodingKey) -> Self {
        self.jwt_key = Some(key);
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

    /// Set the required issuer for the JWT
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set the algorithm used to sign the JWT
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set the leeway (in seconds) to account for clock skew
    pub fn with_leeway(mut self, seconds: u64) -> Self {
        self.leeway = seconds;
        self
    }

    /// Enable or disable expiration validation
    pub fn validate_expiration(mut self, validate: bool) -> Self {
        self.validate_exp = validate;
        self
    }

    /// Enable or disable not-before validation
    pub fn validate_not_before(mut self, validate: bool) -> Self {
        self.validate_nbf = validate;
        self
    }

    /// Enable or disable audience validation
    pub fn validate_audience(mut self, validate: bool) -> Self {
        self.validate_aud = validate;
        self
    }

    /// Build the JWTValidator instance
    pub fn build(self) -> Result<JWTValidator, Error> {
        let jwt_key = self
            .jwt_key
            .ok_or_else(|| ErrorUnauthorized("JWT key is required"))?;

        let mut validation = Validation::new(self.algorithm);

        // Set audiences if provided
        if !self.audiences.is_empty() {
            validation.set_audience(&self.audiences);
        }

        // Set issuer if provided
        if let Some(issuer) = self.issuer {
            validation.set_issuer(&[issuer]);
        }

        // Set validation options
        validation.leeway = self.leeway;
        validation.validate_exp = self.validate_exp;
        validation.validate_nbf = self.validate_nbf;
        validation.validate_aud = self.validate_aud;

        Ok(JWTValidator {
            jwt_key: Arc::new(jwt_key),
            validation: Arc::new(validation),
        })
    }
}

impl JWTValidator {
    /// Create a new builder for configuring the JWT validator
    pub fn builder() -> JWTValidatorBuilder {
        JWTValidatorBuilder::new()
    }

    /// Create a simple JWT validator with minimal configuration
    pub fn new<P: AsRef<Path>>(
        jwt_key_file: P,
        audience: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::builder()
            .with_rsa_pem_key_file(jwt_key_file)?
            .with_audience(audience)
            .build()
    }
}

impl TokenValidator for JWTValidator {
    fn validate_token<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AuthInfo, Error>> + Send + 'a>> {
        Box::pin(async move {
            // Decode and validate the token
            match decode::<Claims>(token, &self.jwt_key, &self.validation) {
                Ok(token_data) => {
                    // Convert claims to AuthInfo
                    // Use name if available, otherwise use sub
                    let name = token_data
                        .claims
                        .name
                        .clone()
                        .unwrap_or_else(|| token_data.claims.sub.clone());
                    Ok(AuthInfo {
                        name,
                        sub: token_data.claims.sub,
                        groups: token_data.claims.groups,
                    })
                }
                Err(e) => {
                    // Return specific error based on validation failure
                    Err(ErrorUnauthorized(format!("Invalid JWT: {}", e)))
                }
            }
        })
    }
}
