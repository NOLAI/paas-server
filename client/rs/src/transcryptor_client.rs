use chrono::{DateTime, Utc};
use libpep::distributed::key_blinding::SessionKeyShare;
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::high_level::data_types::{EncryptedPseudonym};
use serde::{Deserialize, Serialize};
use paas_server::application::sessions::StartSessionResponse;
use paas_server::application::status::{StatusResponse, SystemId};
use paas_server::application::transcrypt::{PseudonymizationBatchRequest, PseudonymizationBatchResponse, PseudonymizationRequest, PseudonymizationResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscryptorConfig {
    pub system_id: SystemId,
    pub url: String,
    pub auth_token: String, // TODO: Auth should be a separate struct
}
pub enum TranscryptorState {
    Unknown,
    Error,
    Online,
}
pub struct TranscryptorStatus {
    pub state: TranscryptorState,
    pub last_checked: Option<DateTime<Utc>>,
}
/// A client that communicates with a single Transcryptor.
pub struct TranscryptorClient{
    pub(crate) config: TranscryptorConfig,
    status: TranscryptorStatus,
    session_id: Option<EncryptionContext>,
}

impl TranscryptorClient {
    /// Create a new TranscryptorClient with the given configuration.
    pub fn new(config: TranscryptorConfig) -> Self {
        Self {
            config,
            status: TranscryptorStatus {
                state: TranscryptorState::Unknown,
                last_checked: None,
            },
            session_id: None,
        }
    }

    /// Check the status of the transcryptor.
    pub async fn check_status(&mut self) -> Result<(), reqwest::Error> {
        let response = reqwest::Client::new()
            .get(format!("{}/status", self.config.url))
            .header("Authorization", format!("Bearer {}", self.config.auth_token))
            .send()
            .await?;
        let _session = response.json::<StatusResponse>().await?;
        self.status = TranscryptorStatus {
            state: TranscryptorState::Online,
            last_checked: Some(chrono::offset::Local::now().into()), // TODO use the time from the response
        };
        Ok(())
    }

    /// Start a new session with the transcryptor.
    pub async fn start_session(&mut self) -> Result<(EncryptionContext, SessionKeyShare), reqwest::Error> {
        let response = reqwest::Client::new()
            .get(format!("{}/session/start", self.config.url))
            .header("Authorization", format!("Bearer {}", self.config.auth_token))
            .send()
            .await?;
        let session = response.json::<StartSessionResponse>().await?;
        self.session_id = Some(session.session_id.clone());
        Ok((session.session_id, session.key_share))
    }

    // TODO: end the session

    /// Ask the transcryptor pseudonymize an encrypted pseudonym.
    pub async fn pseudonymize(&self, encrypted_pseudonym: &EncryptedPseudonym, domain_from: &PseudonymizationDomain, domain_to: &PseudonymizationDomain, session_from: &EncryptionContext, session_to: &EncryptionContext) -> Result<EncryptedPseudonym, reqwest::Error> {
        let request = PseudonymizationRequest {
            encrypted_pseudonym: *encrypted_pseudonym,
            domain_from: domain_from.clone(),
            domain_to: domain_to.clone(),
            session_from: session_from.clone(),
            session_to: session_to.clone(),
        };
        let response = reqwest::Client::new()
            .post(format!("{}/pseudonymize", self.config.url))
            .header("Authorization", format!("Bearer {}", self.config.auth_token))
            .json(&request)
            .send()
            .await?;
        let pseudo_response = response.json::<PseudonymizationResponse>().await?;
        Ok(pseudo_response.encrypted_pseudonym)
    }

    /// Ask the transcryptor to pseudonymize a batch of encrypted pseudonyms.
    pub async fn pseudonymize_batch(&self, encrypted_pseudonyms: Vec<EncryptedPseudonym>, domain_from: &PseudonymizationDomain, domain_to: &PseudonymizationDomain, session_from: &EncryptionContext, session_to: &EncryptionContext) -> Result<Vec<EncryptedPseudonym>, reqwest::Error> {
        let request = PseudonymizationBatchRequest {
            encrypted_pseudonyms: encrypted_pseudonyms.to_vec(),
            domain_from: domain_from.clone(),
            domain_to: domain_to.clone(),
            session_from: session_from.clone(),
            session_to: session_to.clone(),
        };
        let response = reqwest::Client::new()
            .post(format!("{}/pseudonymize_batch", self.config.url))
            .header("Authorization", format!("Bearer {}", self.config.auth_token))
            .json(&request)
            .send()
            .await?;
        let pseudo_response = response.json::<PseudonymizationBatchResponse>().await?;
        Ok(pseudo_response.encrypted_pseudonyms)
    }
}