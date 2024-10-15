use libpep::arithmetic::ScalarNonZero;
use libpep::distributed::{BlindingFactor, PEPSystem};
use libpep::high_level::{EncryptionSecret, PseudonymizationSecret};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug)]
struct PEPSystemConfig {
    pseudonymization_secret: String,
    rekeying_secret: String,
    blinding_factor: String,
}

pub fn create_pep_crypto_system(resource_file: &str) -> PEPSystem {
    // Create PEP system
    let file_content = fs::read_to_string(resource_file).expect("Failed to read config file");
    let pep_system_config: PEPSystemConfig =
        serde_yml::from_str(&file_content).expect("Failed to parse token file");

    let blinding_factor = BlindingFactor(
        ScalarNonZero::decode_from_hex(pep_system_config.blinding_factor.as_str())
            .expect("Failed to decode blinding factor"),
    );

    PEPSystem::new(
        PseudonymizationSecret(pep_system_config.pseudonymization_secret),
        EncryptionSecret(pep_system_config.rekeying_secret),
        blinding_factor,
    )
}
