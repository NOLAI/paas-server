use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use log::{error, warn};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PAASServerError {
    #[error("User not authenticated")]
    NotAuthenticated,

    #[error("Could not start, end or retrieve session")]
    SessionError(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Invalid session format: {0}")]
    InvalidSessionFormat(String),

    #[error("Unknown or expired session: {0}")]
    InvalidSession(String),

    #[error("Unauthorized session access")]
    UnauthorizedSession,

    #[error("Access denied: not allowed to transcrypt from {from} to {to}")]
    AccessDenied { from: String, to: String },
}

impl ResponseError for PAASServerError {
    fn status_code(&self) -> StatusCode {
        match &self {
            Self::NotAuthenticated => StatusCode::UNAUTHORIZED,
            Self::SessionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidSessionFormat(_) => StatusCode::BAD_REQUEST,
            Self::InvalidSession(_) => StatusCode::NOT_FOUND,
            Self::UnauthorizedSession => StatusCode::FORBIDDEN,
            Self::AccessDenied { .. } => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let error_message = self.to_string();

        match self {
            Self::NotAuthenticated => {
                warn!("Authentication failure: status_code={}, error={}", status.as_u16(), error_message);
            }
            Self::SessionError(source) => {
                error!(
                    "Session operation error: status_code={}, error={}, source={:?}",
                    status.as_u16(), error_message, source
                );
            }
            Self::InvalidSessionFormat(format) => {
                warn!(
                    "Invalid session format: status_code={}, error={}, format={}",
                    status.as_u16(), error_message, format
                );
            }
            Self::InvalidSession(session) => {
                warn!(
                    "Invalid session: status_code={}, error={}, session={}",
                    status.as_u16(), error_message, session
                );
            }
            Self::UnauthorizedSession => {
                warn!(
                    "Unauthorized session access: status_code={}, error={}",
                    status.as_u16(), error_message
                );
            }
            Self::AccessDenied { from, to } => {
                warn!(
                    "Access denied for transcryption: status_code={}, error={}, from={}, to={}",
                    status.as_u16(), error_message, from, to
                );
            }
        }

        // For security, don't expose internal error details in production
        let response_body = if status == StatusCode::INTERNAL_SERVER_ERROR {
            json!({
                "error": "An internal server error occurred"
            })
        } else {
            json!({
                "error": error_message
            })
        };

        HttpResponse::build(status)
            .content_type("application/json")
            .json(response_body)
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for PAASServerError {
    fn from(source: Box<dyn std::error::Error + Send + Sync>) -> Self {
        error!("Converting generic error to PAASServerError: error={:?}", source);
        PAASServerError::SessionError(source)
    }
}
