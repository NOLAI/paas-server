use libpep::factors::{EncryptionSecret, PseudonymizationSecret};
use libpep::keys::distribution::BlindingFactor;
use libpep::transcryptor::DistributedTranscryptor;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug)]
pub struct PEPSystemConfig {
    pseudonymization_secret: String,
    rekeying_secret: String,
    blinding_factor: String,
}

pub fn create_pep_crypto_system(system_config_file: &str) -> DistributedTranscryptor {
    let file_content =
        fs::read_to_string(system_config_file).expect("Failed to read PEP system config file");
    let pep_system_config: PEPSystemConfig =
        serde_yml::from_str(&file_content).expect("Failed to PEP system config file");

    let blinding_factor = BlindingFactor::from_hex(pep_system_config.blinding_factor.as_str())
        .expect("Failed to decode blinding factor");

    DistributedTranscryptor::new(
        PseudonymizationSecret::from(pep_system_config.pseudonymization_secret.into_bytes()),
        EncryptionSecret::from(pep_system_config.rekeying_secret.into_bytes()),
        blinding_factor,
    )
}
