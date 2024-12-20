use libpep::distributed::key_blinding::BlindedGlobalSecretKey;
use libpep::distributed::systems::PEPClient;
use libpep::high_level::keys::GlobalPublicKey;
use serde::{Deserialize, Serialize};
use crate::transcryptor_client::{TranscryptorClient, TranscryptorConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymServiceConfig {
    pub blinded_global_secret_key: BlindedGlobalSecretKey,
    pub global_public_key: GlobalPublicKey,
    pub transcryptors: Vec<TranscryptorConfig>
}

pub struct PseudonymService {
    config: PseudonymServiceConfig,
    transcryptors: Vec<TranscryptorClient>,
    pep_client: Option<PEPClient>
}

impl PseudonymService {
    pub fn new(config: PseudonymServiceConfig) -> Self {
        let transcryptors = config.transcryptors.iter().map(|c| {
            TranscryptorClient::new(c.clone())
        }).collect();
        Self {
            config,
            transcryptors,
            pep_client: None
        }
    }

    pub(crate) fn create_pep_client(&mut self) {
        let sks = self.transcryptors.iter().map(|mut t| t.start_session()).collect();

    }
    pub async fn pseudonymize(&self, encrypted_pseudonym: String) -> String {
        let pseudonym = self.pep_client.pseudonymize(encrypted_pseudonym.clone()).await;
        let mut pseudonym = pseudonym.unwrap();
        for transcryptor in &self.transcryptors {
            pseudonym = transcryptor.pseudonymize(pseudonym).await.unwrap();
        }
        pseudonym
    }
    pub async fn pseudonymize_batch(&self, encrypted_pseudonyms: Vec<String>) -> Vec<String> {
        let mut pseudonyms = self.pep_client.pseudonymize_batch(encrypted_pseudonyms.clone()).await;
        for transc

}