//! `age-plugin-ssh-agent` binary.
//!
//! age runs it with `--age-plugin=<state machine>`; users run it with `--list-identities` or
//! `--key-gen --identity <key>`. All modes connect to the agent first.

use age_plugin::run_state_machine;
use age_plugin_ssh_agent::agent::{Agent, AgentClient};
use age_plugin_ssh_agent::identity::Identity;
use age_plugin_ssh_agent::plugin;
use chrono::{DateTime, FixedOffset, Local, SecondsFormat};
use clap::Parser;
use ssh_agent_lib::blocking::Client;
use std::os::unix::net::UnixStream;

use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;

use ssh_agent_lib::ssh_key::HashAlg::Sha256;

#[derive(Debug, Parser)]
#[command(name = "age-plugin-ssh-agent")]
#[command(about = "An age plugin for ssh-agent-backed keys", long_about = None)]
struct Arguments {
    #[arg(help = "generate a new ssh-agent-backed keypair", long)]
    key_gen: bool,
    #[arg(
        help = "identity to use for keypair generation (SHA256 fingerprint, including \"SHA256:\")",
        long
    )]
    identity: Option<String>,
    #[arg(
        help = "list available and valid (Ed25519) identities in the agent",
        long
    )]
    list_identities: bool,
    #[arg(help = "specify the output file", short, long)]
    output: Option<String>,
    #[arg(help = "ssh-agent socket path", long, env = "SSH_AUTH_SOCK")]
    agent_socket: Option<String>,
    #[arg(help = "run the given age plugin state machine", long)]
    age_plugin: Option<String>,
}

fn main() -> io::Result<()> {
    let args = Arguments::parse();

    let agent_socket = args.agent_socket.unwrap_or_else(|| {
        eprintln!("no agent socket path specified and SSH_AUTH_SOCK env var isn't set");
        std::process::exit(1);
    });

    let stream = match UnixStream::connect(agent_socket) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("failed to connect to socket: {e}");
            std::process::exit(1);
        }
    };
    let mut agent = Agent::new(Client::new(stream));

    if args.list_identities {
        match format_identities(&mut agent) {
            Ok(identity_list) => {
                println!("{identity_list}");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("failed to retrieve identities: {e}");
                std::process::exit(1);
            }
        }
    }

    if args.key_gen {
        if args.identity.is_none() {
            eprintln!("--identity must be supplied with --key-gen");
            std::process::exit(1);
        }

        let identity_file = match generate_identity(&mut agent, &args.identity.unwrap()) {
            Ok(identity_file) => identity_file,
            Err(e) => {
                eprintln!("failed to generate keys: {e}");
                std::process::exit(1);
            }
        };

        if let Err(e) = write_identity(&identity_file, args.output.as_deref()) {
            eprintln!("failed to write identity: {e}");
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if let Some(state_machine) = args.age_plugin {
        // The plugin was started by an age client; run the state machine.
        run_state_machine(&state_machine, plugin::Handler { agent })?;
        return Ok(());
    }

    // Here you can assume the binary is being run directly by a user,
    // and perform administrative tasks like generating keys.

    Ok(())
}

fn format_identities<A: AgentClient>(store: &mut Agent<A>) -> Result<String, Box<dyn Error>> {
    let identity_list = store
        .identities()?
        .iter()
        .map(|identity| {
            let fingerprint = identity.credential.key_data().fingerprint(Sha256);
            let comment = &identity.comment;
            format!("{fingerprint} {comment}")
        })
        .collect::<Vec<String>>()
        .join("\n");
    Ok(identity_list)
}
struct AgeIdentityFile {
    created: DateTime<FixedOffset>,
    identity: Identity,
    recipient: age::x25519::Recipient,
}

// this needs to always match age; age-plugin has a print_new_identity()
// function but it doesn't let you write to a file...
impl fmt::Display for AgeIdentityFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "# created: {}",
            self.created.to_rfc3339_opts(SecondsFormat::Secs, true)
        )?;
        writeln!(f, "# recipient: {}", self.recipient)?;
        write!(f, "{}", self.identity)
    }
}

fn generate_identity<A: AgentClient>(
    agent: &mut Agent<A>,
    identity: &str,
) -> Result<AgeIdentityFile, Box<dyn Error>> {
    let agent_identity = agent.find_string(identity)?;
    let identity = Identity::new(agent_identity)?;
    let recipient = identity.age_recipient(agent)?;

    Ok(AgeIdentityFile {
        created: Local::now().fixed_offset(),
        identity,
        recipient,
    })
}

fn write_identity(new_identity: &AgeIdentityFile, output: Option<&str>) -> io::Result<()> {
    let Some(path) = output else {
        println!("{new_identity}");
        return Ok(());
    };

    // never overwrite an existing identity: losing its secret makes its files unrecoverable
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{new_identity}")?;

    // age weirdly prints this to stderr and we're copying its behavior...
    eprintln!("Public key: {}", new_identity.recipient);

    Ok(())
}

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod common;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::common::{
        KAT_IDENTITY, KAT_RECIPIENT, MockAgent, ed25519_identity, kat_identity, sk_ed25519_identity,
    };

    fn kat_identity_file() -> AgeIdentityFile {
        AgeIdentityFile {
            created: DateTime::parse_from_rfc3339("2026-10-09T12:34:56-07:00").unwrap(),
            identity: kat_identity(),
            recipient: KAT_RECIPIENT.parse().unwrap(),
        }
    }

    #[test]
    fn formats_ed25519_identities() {
        let mut agent = Agent::new(MockAgent::new(vec![
            ed25519_identity(1, "laptop"),
            sk_ed25519_identity(2, "fido"),
            ed25519_identity(3, "desktop"),
        ]));
        let desktop = ed25519_identity(3, "desktop")
            .credential
            .key_data()
            .fingerprint(Sha256);

        assert_eq!(
            format_identities(&mut agent).unwrap(),
            format!("SHA256:RXm/ruZ0eTzRXKwi1AQEDynB0VgHQ2ac9KPSFdf/YnA laptop\n{desktop} desktop")
        );
    }

    #[test]
    fn identity_file_matches_age_format() {
        assert_eq!(
            kat_identity_file().to_string(),
            format!(
                "# created: 2026-10-09T12:34:56-07:00\n# recipient: {KAT_RECIPIENT}\n{KAT_IDENTITY}"
            )
        );
    }

    #[test]
    fn identity_file_writes_utc_as_z() {
        let file = AgeIdentityFile {
            created: DateTime::parse_from_rfc3339("2026-10-09T12:34:56+00:00").unwrap(),
            ..kat_identity_file()
        };

        assert!(
            file.to_string()
                .starts_with("# created: 2026-10-09T12:34:56Z\n")
        );
    }

    #[test]
    fn generates_an_identity_for_the_requested_key() {
        let mut agent = Agent::new(MockAgent::new(vec![
            ed25519_identity(2, "desktop"),
            ed25519_identity(1, "laptop"),
        ]));

        let file = generate_identity(
            &mut agent,
            "SHA256:RXm/ruZ0eTzRXKwi1AQEDynB0VgHQ2ac9KPSFdf/YnA",
        )
        .unwrap();

        // only the laptop key is available, so this fails if another key was picked
        let mut laptop = Agent::new(MockAgent::new(vec![ed25519_identity(1, "laptop")]));
        assert_eq!(
            file.recipient,
            file.identity.age_recipient(&mut laptop).unwrap()
        );
    }

    #[test]
    fn generate_errors_for_unknown_key() {
        let mut agent = Agent::new(MockAgent::new(vec![ed25519_identity(1, "laptop")]));
        let unknown = ed25519_identity(2, "desktop")
            .credential
            .key_data()
            .fingerprint(Sha256);

        assert!(generate_identity(&mut agent, &unknown.to_string()).is_err());
    }

    #[test]
    fn writes_identity_file_once_with_private_permissions() {
        let path = std::env::temp_dir().join(format!(
            "age-plugin-ssh-agent-test-{}.txt",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let file = kat_identity_file();

        write_identity(&file, path.to_str()).unwrap();
        let written = fs::read_to_string(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        let overwrite = write_identity(&kat_identity_file(), path.to_str());
        let after = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).unwrap();

        assert_eq!(written, format!("{file}\n"));
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(overwrite.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(after, written);
    }
}
