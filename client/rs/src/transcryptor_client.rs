use chrono::{DateTime, Utc};
use libpep::distributed::key_blinding::SessionKeyShare;
use libpep::high_level::contexts::{EncryptionContext, PseudonymizationContext};
use libpep::high_level::data_types::EncryptedPseudonym;
use serde::{Deserialize, Serialize};
use paas_server::application::sessions::{StartSessionResponse};
use paas_server::application::status::{StatusResponse};
use paas_server::application::transcrypt::{PseudonymizationRequest, PseudonymizationResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscryptorConfig {
    pub system_id: String,
    pub url: String,
    pub jwt: String,
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
pub struct TranscryptorClient{
    config: TranscryptorConfig,
    status: TranscryptorStatus,
    session_id: Option<String>,
}

impl TranscryptorClient {
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
    pub async fn check_status(&mut self) -> Result<(), reqwest::Error> {
        let response = reqwest::Client::new()
            .get(&format!("{}/status", self.config.url))
            .header("Authorization", format!("Bearer {}", self.config.jwt))
            .send()
            .await?;
        let session = response.json::<StatusResponse>().await?;
        self.status = TranscryptorStatus {
            state: TranscryptorState::Online,
            last_checked: Some(chrono::offset::Local::now().into()),
        };
        Ok(())
    }

    pub async fn start_session(&mut self) -> Result<(String, SessionKeyShare), reqwest::Error> {
        let response = reqwest::Client::new()
            .get(&format!("{}/session/start", self.config.url))
            .header("Authorization", format!("Bearer {}", self.config.jwt))
            .send()
            .await?;
        let session = response.json::<StartSessionResponse>().await?;
        let session_key_share = session.key_share.clone();
        self.session_id = Some(session.session_id.clone());
        Ok((session.session_id, session_key_share))
    }

    pub async fn pseudonymize(&self, encrypted_pseudonym: &EncryptedPseudonym, pseudo_context_from: &PseudonymizationContext, pseudo_context_to: &PseudonymizationContext, encryption_context_from: &EncryptionContext, encryption_context_to: &EncryptionContext) -> Result<EncryptedPseudonym, reqwest::Error> {
        let request = PseudonymizationRequest {
            encrypted_pseudonym: encrypted_pseudonym.to_base64(),
            pseudonym_context_from: pseudo_context_from.clone(),
            pseudonym_context_to: pseudo_context_to.clone(),
            enc_context: encryption_context_from.clone(),
            dec_context: encryption_context_to.clone(),
        };
        let response = reqwest::Client::new()
            .post(&format!("{}/pseudonymize", self.config.url))
            .header("Authorization", format!("Bearer {}", self.config.jwt))
            .json(&request)
            .send()
            .await?;
        let encrypted_pseudonym = response.json::<PseudonymizationResponse>().await?;
        Ok(encrypted_pseudonym)
    }
}