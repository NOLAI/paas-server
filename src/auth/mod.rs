pub mod core;
pub mod jwt;
pub mod oidc;
pub mod token;

use actix_web::Error;
use core::TokenValidator;
use jwt::JWTValidator;
use oidc::OIDCValidator;
use std::future::Future;
use std::pin::Pin;
use token::SimpleTokenValidator;

// Re-export key types from core
pub use core::{AuthInfo, Authentication};

/// AuthType combines all possible validators into a single enum
/// which itself implements the TokenValidator trait
#[derive(Clone)]
pub enum AuthType {
    SimpleToken(SimpleTokenValidator),
    JWT(JWTValidator),
    OIDC(OIDCValidator),
}

impl TokenValidator for AuthType {
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
