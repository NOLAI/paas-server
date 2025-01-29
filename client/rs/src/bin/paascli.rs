use clap::{Arg, Command};
use libpep::high_level::contexts::PseudonymizationDomain;
use libpep::high_level::data_types::{Encrypted, EncryptedPseudonym};
use libpep::high_level::keys::{SessionPublicKey, SessionSecretKey};
use paas_client::auth::AuthTokens;
use paas_client::pseudonym_service::{PseudonymService, PseudonymServiceConfig};
use paas_client::sessions::EncryptionContexts;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize)]
struct PseudonymServiceDump {
    sessions: EncryptionContexts,
    session_keys: (SessionPublicKey, SessionSecretKey),
}

#[tokio::main]
async fn main() {
    let matches = Command::new("paascli")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(
            Command::new("pseudonymize")
                .about("Pseudonymize an encrypted pseudonym from one domain to another")
                .arg(
                    Arg::new("encrypted_pseudonym")
                        .help("The encrypted pseudonym to pseudonymize")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("sessions")
                        .help("The sessions in which the pseudonym was encrypted")
                        .required(true)
                        .index(2),
                )
                .arg(
                    Arg::new("domain_from")
                        .help("The source domain of the pseudonym")
                        .required(true)
                        .index(3),
                )
                .arg(
                    Arg::new("domain_to")
                        .help("The target domain of the pseudonym")
                        .required(true)
                        .index(4),
                )
                .arg(
                    Arg::new("config")
                        .help("Path to the configuration file")
                        .required(true)
                        .long("config")
                        .short('c')
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("tokens")
                        .help("Path to the file containing auth tokens")
                        .required(true)
                        .long("tokens")
                        .short('t')
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("no_decrypt")
                        .help("Only show the transcrypted result without decrypting")
                        .long("no-decrypt")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("state_path")
                        .help("Path to restore state from and dump state to")
                        .long("state")
                        .short('s')
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("pseudonymize") {
        let config_path = matches
            .get_one::<String>("config")
            .expect("config path is required");
        let config_contents = fs::read_to_string(config_path).expect("Failed to read config file");
        let config: PseudonymServiceConfig =
            serde_json::from_str(&config_contents).expect("Failed to parse config");

        let tokens_path = matches
            .get_one::<String>("tokens")
            .expect("tokens path is required");
        let tokens_contents = fs::read_to_string(tokens_path).expect("Failed to read tokens file");
        let tokens: AuthTokens =
            serde_json::from_str(&tokens_contents).expect("Failed to parse tokens");

        let state_path = matches.get_one::<String>("state_path");

        let mut service = if let Some(path) = state_path {
            if let Ok(contents) = fs::read_to_string(path) {
                let dump: PseudonymServiceDump =
                    serde_json::from_str(&contents).expect("Failed to deserialize service state");
                PseudonymService::restore(config, tokens, dump.sessions, dump.session_keys)
            } else {
                PseudonymService::new(config, tokens)
            }
        } else {
            PseudonymService::new(config, tokens)
        };

        let encrypted_pseudonym_str = matches
            .get_one::<String>("encrypted_pseudonym")
            .expect("encrypted_pseudonym is required");

        let encrypted_pseudonym = EncryptedPseudonym::from_base64(encrypted_pseudonym_str)
            .expect("Failed to deserialize encrypted_pseudonym");

        let sessions_str = matches
            .get_one::<String>("sessions")
            .expect("sessions is required");

        let sessions =
            EncryptionContexts::decode(sessions_str).expect("Failed to deserialize sessions");

        let domain_from_str = matches
            .get_one::<String>("domain_from")
            .expect("domain_from is required");

        let domain_from = PseudonymizationDomain::from(domain_from_str);

        let domain_to_str = matches
            .get_one::<String>("domain_to")
            .expect("domain_to is required");

        let domain_to = PseudonymizationDomain::from(domain_to_str);

        let result = service
            .pseudonymize(&encrypted_pseudonym, &sessions, &domain_from, &domain_to)
            .await;

        if matches.get_flag("no_decrypt") {
            eprint!("Transcryption returned: ");
            println!("{}", &result.as_base64());
        } else {
            let pseudonym = service.decrypt(&result).await;
            eprint!("Decrypted pseudonym: ");
            println!("{}", &pseudonym.encode_as_hex());
        }

        if let Some(path) = state_path {
            let (sessions, session_keys) = service.dump();
            let dump = PseudonymServiceDump {
                sessions,
                session_keys,
            };
            let serialized =
                serde_json::to_string(&dump).expect("Failed to serialize service dump");
            fs::write(path, serialized).expect("Failed to write state dump to file");
        }
    }
}
