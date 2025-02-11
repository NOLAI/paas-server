use libpep::high_level::contexts::{EncryptionContext, PseudonymizationDomain};
use libpep::high_level::data_types::EncryptedPseudonym;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug)]
/// An API request to transcrypt a single encrypted pseudonym.
pub struct PseudonymizationRequest {
    /// The encrypted pseudonym.
    pub encrypted_pseudonym: EncryptedPseudonym,
    /// The domain of the encrypted pseudonym.
    pub domain_from: PseudonymizationDomain,
    /// The domain to transcrypt the pseudonym to.
    pub domain_to: PseudonymizationDomain,
    /// The session the pseudonym was encrypted in associated with this server.
    pub session_from: EncryptionContext,
    /// The session the pseudonym should be decryptable in associated with this server.
    pub session_to: EncryptionContext,
}
#[derive(Serialize, Deserialize)]
pub struct PseudonymizationResponse {
    /// The transcrypted pseudonym.
    pub encrypted_pseudonym: EncryptedPseudonym,
}

#[derive(Serialize, Deserialize, Debug)]
/// An API request to transcrypt multiple encrypted pseudonyms.
pub struct PseudonymizationBatchRequest {
    /// The encrypted pseudonyms.
    pub encrypted_pseudonyms: Vec<EncryptedPseudonym>,
    /// The domain of the encrypted pseudonyms.
    pub domain_from: PseudonymizationDomain,
    /// The domain to transcrypt the pseudonyms to.
    pub domain_to: PseudonymizationDomain,
    /// The session the pseudonyms were encrypted in, associated with this server.
    pub session_from: EncryptionContext,
    /// The session the pseudonyms should be decryptable in, associated with this server.
    pub session_to: EncryptionContext,
}

#[derive(Serialize, Deserialize)]
pub struct PseudonymizationBatchResponse {
    /// The transcrypted pseudonyms.
    /// Watch out: the order of the encrypted pseudonyms will be randomly permuted to break linkability.
    pub encrypted_pseudonyms: Vec<EncryptedPseudonym>,
}
