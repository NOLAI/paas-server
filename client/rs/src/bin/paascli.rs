mod commands;

use clap::{Arg, Command};
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("paascli")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("config")
                .help("Path to the configuration file")
                .long("config")
                .short('c')
                .global(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("tokens")
                .help("Path to the file containing auth tokens")
                .long("tokens")
                .short('t')
                .global(true)
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("state_path")
                .help("Path to restore state from and dump state to")
                .long("state")
                .short('s')
                .global(true)
                .value_parser(clap::value_parser!(String)),
        )
        .subcommand(commands::pseudonymize::command())
        .subcommand(commands::encrypt::command())
        .get_matches();

    // Load the configuration and auth tokens
    let config_path = matches
        .get_one::<String>("config")
        .ok_or("config path is required")?;
    let config_contents =
        fs::read_to_string(config_path).map_err(|e| format!("Failed to read config file: {e}"))?;
    let config: PseudonymServiceConfig = serde_json::from_str(&config_contents)
        .map_err(|e| format!("Failed to parse config: {e}"))?;

    let tokens_path = matches
        .get_one::<String>("tokens")
        .ok_or("tokens path is required")?;
    let tokens_contents =
        fs::read_to_string(tokens_path).map_err(|e| format!("Failed to read tokens file: {e}"))?;
    let tokens: AuthTokens = serde_json::from_str(&tokens_contents)
        .map_err(|e| format!("Failed to parse tokens: {e}"))?;

    // Restore the service from the state dump if it exists
    let state_path = matches.get_one::<String>("state_path");
    let mut service = if let Some(path) = state_path {
        if let Ok(contents) = fs::read_to_string(path) {
            let dump: PseudonymServiceDump = serde_json::from_str(&contents)
                .map_err(|e| format!("Failed to deserialize service state: {e}"))?;
            PseudonymService::restore(config, tokens, dump.sessions, dump.session_keys)?
        } else {
            PseudonymService::new(config, tokens)?
        }
    } else {
        PseudonymService::new(config, tokens)?
    };

    // Execute the subcommand
    match matches.subcommand() {
        Some(("pseudonymize", matches)) => {
            commands::pseudonymize::execute(matches, &mut service).await?;
        }
        Some(("encrypt", matches)) => {
            commands::encrypt::execute(matches, &mut service).await?;
        }
        _ => {
            println!("No command specified. Use --help for usage information.");
        }
    }

    // Write the state dump to the file
    if let Some(path) = state_path {
        let (sessions, session_keys) = service.dump()?;
        let dump = PseudonymServiceDump {
            sessions,
            session_keys,
        };
        let serialized = serde_json::to_string(&dump)
            .map_err(|e| format!("Failed to parse service dump: {e}"))?;
        fs::write(path, serialized)
            .map_err(|e| format!("Failed to write dump state to file: {e}"))?;
    }
    Ok(())
}
