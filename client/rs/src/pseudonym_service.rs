use std::collections::HashMap;

use crate::auth::AuthTokens;
use crate::error::ClientError;
use crate::sessions::EncryptionContexts;
use crate::transcryptor_client::{TranscryptorClient, TranscryptorConfig};
use libpep::distributed::key_blinding::BlindedGlobalSecretKey;
use libpep::distributed::systems::PEPClient;
use libpep::high_level::contexts::PseudonymizationDomain;
use libpep::high_level::data_types::{Encryptable, Encrypted, EncryptedPseudonym};
use libpep::high_level::keys::{GlobalPublicKey, SessionPublicKey, SessionSecretKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymServiceConfig {
    pub blinded_global_secret_key: BlindedGlobalSecretKey,
    pub global_public_key: GlobalPublicKey,
    pub transcryptors: Vec<TranscryptorConfig>,
} // TODO servers should host these configs in a well-known location

#[derive(Clone)]
pub struct PseudonymService {
    config: PseudonymServiceConfig,
    transcryptors: Vec<TranscryptorClient>,
    pub pep_crypto_client: Option<PEPClient>, // TODO make this private
}

/// Convert encrypted pseudonyms into your own pseudonyms, using the [PseudonymService].
/// The service will communicate with the configured transcryptors, and wraps around a [PEPClient] for cryptographic operations.
impl PseudonymService {
    pub fn new(
        config: PseudonymServiceConfig,
        auth_tokens: AuthTokens,
    ) -> Result<Self, ClientError> {
        let mut transcryptors = Vec::new();
        let mut missing_auth_tokens = Vec::new();
        for transcriptor in &config.transcryptors {
            if let Some(token) = auth_tokens.get(&transcriptor.system_id) {
                transcryptors.push(TranscryptorClient::new(
                    transcriptor.clone(),
                    token.to_owned(),
                ));
            } else {
                missing_auth_tokens.push(transcriptor.system_id.clone());
            }
        }

        if !missing_auth_tokens.is_empty() {
            return Err(ClientError::MissingAuthTokens(missing_auth_tokens));
        }
        Ok(Self {
            config,
            transcryptors,
            pep_crypto_client: None,
        })
    }

    /// Restore a [PseudonymService] from a dumped state.
    pub fn restore(
        config: PseudonymServiceConfig,
        auth_tokens: AuthTokens,
        session_ids: EncryptionContexts,
        session_keys: (SessionPublicKey, SessionSecretKey),
    ) -> Result<Self, ClientError> {
        let mut transcryptors = Vec::new();
        let mut missing_auth_tokens = Vec::new();
        let mut missing_sessions = Vec::new();
        for transcriptor in &config.transcryptors {
            if let Some(token) = auth_tokens.get(&transcriptor.system_id) {
                if let Some(session_id) = session_ids.get(&transcriptor.system_id) {
                    transcryptors.push(TranscryptorClient::restore(
                        transcriptor.clone(),
                        token.to_owned(),
                        session_id.to_owned(),
                    ));
                } else {
                    missing_sessions.push(transcriptor.system_id.clone());
                }
            } else {
                missing_auth_tokens.push(transcriptor.system_id.clone());
            }
        }

        if !missing_sessions.is_empty() {
            return Err(ClientError::MissingTranscryptorSessions(missing_sessions));
        }
        if !missing_auth_tokens.is_empty() {
            return Err(ClientError::MissingAuthTokens(missing_auth_tokens));
        }
        Ok(Self {
            config,
            transcryptors,
            pep_crypto_client: Some(PEPClient::restore(session_keys.0, session_keys.1)),
        })
    }

    /// Dump the current state of the [PseudonymService].
    pub fn dump(
        &self,
    ) -> Result<(EncryptionContexts, (SessionPublicKey, SessionSecretKey)), ClientError> {
        let session_ids = self.get_current_sessions()?;
        let session_keys = self
            .pep_crypto_client
            .as_ref()
            .ok_or(ClientError::MissingPEPClient)?
            .dump();
        Ok((session_ids, session_keys))
    }

    /// Start a new session with all configured transcryptors, and initialize a [PEPClient] using the session keys.
    pub async fn init(&mut self) -> Result<(), ClientError> {
        let mut sks = vec![];
        for transcryptor in &mut self.transcryptors {
            let (_session_id, key_share) = transcryptor
                .start_session()
                .await
                .map_err(ClientError::NetworkError)?;
            sks.push(key_share);
        }
        self.pep_crypto_client = Some(PEPClient::new(self.config.blinded_global_secret_key, &sks));
        Ok(())
    } // TODO: add a way to check if the session is still valid, and add a way to refresh the session

    // TODO: end the session

    // TODO: check status, and check if system id is correct

    /// Transform an encrypted pseudonym into your own pseudonym.
    pub async fn pseudonymize(
        &mut self,
        encrypted_pseudonym: &EncryptedPseudonym,
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> Result<EncryptedPseudonym, ClientError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }
        let mut transcrypted = *encrypted_pseudonym;
        let mut missing_sessions = Vec::new();
        let mut missing_systems = Vec::new();
        for transcryptor in &self.transcryptors {
            if let Some(system_session) = sessions_from.get(&transcryptor.config.system_id) {
                if let Some(session) = transcryptor.session_id.clone() {
                    transcrypted = transcryptor
                        .pseudonymize(
                            &transcrypted,
                            domain_from,
                            domain_to,
                            system_session,
                            &session,
                        )
                        .await
                        .map_err(ClientError::NetworkError)?;
                } else {
                    missing_sessions.push(transcryptor.config.system_id.clone());
                }
            } else {
                missing_systems.push(transcryptor.config.system_id.clone());
            }
        }
        if !missing_systems.is_empty() {
            return Err(ClientError::MissingTranscryptors(missing_systems));
        }

        if !missing_sessions.is_empty() {
            return Err(ClientError::MissingTranscryptorSessions(missing_sessions));
        }

        Ok(transcrypted)
    }
    // TODO add a way to change the order of transcryptors, and add a way to add new transcryptors

    /// Transform a batch of encrypted pseudonyms into your own pseudonyms.
    /// Notice that the order of the pseudonyms in the input and output vectors are NOT the same, to prevent linking.
    /// If you need to preserve the order, you should call the [pseudonymize] method for each pseudonym individually. (TODO: add a feature flag to preserve order)
    pub async fn pseudonymize_batch(
        &mut self,
        encrypted_pseudonyms: &[EncryptedPseudonym],
        sessions_from: &EncryptionContexts,
        domain_from: &PseudonymizationDomain,
        domain_to: &PseudonymizationDomain,
    ) -> Result<Vec<EncryptedPseudonym>, ClientError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }
        let mut transcrypted = encrypted_pseudonyms.to_vec();
        let mut missing_sessions = Vec::new();
        let mut missing_systems = Vec::new();
        for transcryptor in &self.transcryptors {
            if let Some(system_session) = sessions_from.get(&transcryptor.config.system_id) {
                if let Some(session) = transcryptor.session_id.clone() {
                    transcrypted = transcryptor
                        .pseudonymize_batch(
                            transcrypted,
                            domain_from,
                            domain_to,
                            system_session,
                            &session,
                        )
                        .await
                        .map_err(ClientError::NetworkError)?;
                } else {
                    missing_sessions.push(transcryptor.config.system_id.clone());
                }
            } else {
                missing_systems.push(transcryptor.config.system_id.clone());
            }
        }
        if !missing_systems.is_empty() {
            return Err(ClientError::MissingTranscryptors(missing_systems));
        }

        if !missing_sessions.is_empty() {
            return Err(ClientError::MissingTranscryptorSessions(missing_sessions));
        }

        Ok(transcrypted)
    }

    // TODO add transcypt_batch method

    /// Encrypt a message using the [PEPClient]'s current session.
    pub async fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
        &mut self,
        message: &E,
        rng: &mut R,
    ) -> Result<(E::EncryptedType, EncryptionContexts), ClientError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }
        Ok((
            self.pep_crypto_client
                .as_ref()
                .ok_or(ClientError::MissingPEPClient)?
                .encrypt(message, rng),
            self.get_current_sessions()?.clone(),
        ))
    }

    pub fn get_current_sessions(&self) -> Result<EncryptionContexts, ClientError> {
        let mut encryption_contexts = HashMap::new();
        let mut missing_sessions = Vec::new();
        for transcryptor in &self.transcryptors {
            if let Some(session_id) = transcryptor.session_id.clone() {
                encryption_contexts.insert(transcryptor.config.system_id.clone(), session_id);
            } else {
                missing_sessions.push(transcryptor.config.system_id.clone());
            }
        }

        if missing_sessions.is_empty() {
            Ok(EncryptionContexts(encryption_contexts))
        } else {
            Err(ClientError::MissingTranscryptorSessions(missing_sessions))
        }
    }

    /// Decrypt an encrypted message using the [PEPClient]'s current session.
    pub async fn decrypt<E: Encrypted>(
        &mut self,
        encrypted: &E,
    ) -> Result<E::UnencryptedType, ClientError> {
        if self.pep_crypto_client.is_none() {
            self.init().await?;
        }
        Ok(self
            .pep_crypto_client
            .as_ref()
            .ok_or(ClientError::MissingPEPClient)?
            .decrypt(encrypted))
    }
}
