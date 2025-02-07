use core::fmt;

use paas_common::status::SystemId;

#[derive(Debug)]
pub enum ClientError {
    NetworkError(reqwest::Error),
    MissingTranscryptorSessions(Vec<SystemId>),
    MissingTranscryptors(Vec<SystemId>),
    MissingPEPClient,
    MissingAuthTokens(Vec<SystemId>),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::NetworkError(error) => write!(f, "Network error: {}", error),
            ClientError::MissingTranscryptorSessions(items) => {
                write!(f, "Missing transcryptor errors, for systems: {:?}", items)
            }
            ClientError::MissingTranscryptors(items) => {
                write!(f, "No transcryptor found for systems: {:?}", items)
            }
            ClientError::MissingPEPClient => write!(f, "No PEP client"),
            ClientError::MissingAuthTokens(items) => {
                write!(f, "No authentication tokens found for systems: {:?}", items)
            }
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::NetworkError(error) => Some(error),
            _ => None,
        }
    }
}
