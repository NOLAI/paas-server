use libpep::high_level::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::high_level::data_types::EncryptedPseudonym;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PseudonymizationResponse {
    pub encrypted_pseudonym: EncryptedPseudonym,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PseudonymizationRequest {
    pub encrypted_pseudonym: EncryptedPseudonym,
    pub domain_from: PseudonymizationDomain,
    pub domain_to: PseudonymizationDomain,
    pub session_from: EncryptionContext,
    pub session_to: EncryptionContext,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PseudonymizationBatchRequest {
    pub encrypted_pseudonyms: Vec<EncryptedPseudonym>,
    pub domain_from: PseudonymizationDomain,
    pub domain_to: PseudonymizationDomain,
    pub session_from: EncryptionContext,
    pub session_to: EncryptionContext,
}

#[derive(Serialize, Deserialize)]
pub struct PseudonymizationBatchResponse {
    pub encrypted_pseudonyms: Vec<EncryptedPseudonym>,
}
