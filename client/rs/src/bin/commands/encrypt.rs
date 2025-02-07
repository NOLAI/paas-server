use clap::{Arg, Command};
use libpep::high_level::data_types::{Encryptable, Encrypted, Pseudonym};
use paas_client::pseudonym_service::PseudonymService;
use rand_core::OsRng;

pub fn command() -> Command {
    Command::new("encrypt").about("Encrypt a pseudonym").arg(
        Arg::new("pseudonym")
            .help("The pseudonym value to encrypt")
            .required(true)
            .index(1),
    )
}

pub async fn execute(
    matches: &clap::ArgMatches,
    service: &mut PseudonymService,
) -> Result<(), Box<dyn std::error::Error>> {
    let pseudonym_string = matches
        .get_one::<String>("pseudonym")
        .ok_or("pseudonym is required")?;
    let pseudonym =
        Pseudonym::decode_from_hex(pseudonym_string).ok_or("Failed to decode pseudonym")?;

    let rng = &mut OsRng;

    let (encrypted, sessions) = service.encrypt(&pseudonym, rng).await?;

    println!("Encrypted pseudonym: {}", encrypted.as_base64());
    println!("Sessions: {}", sessions.encode());
    Ok(())
}
