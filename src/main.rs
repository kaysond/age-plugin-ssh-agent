use age_plugin::run_state_machine;
use age_plugin_ssh_agent::agent::{IdentityStore, UnixIdentityStore};
use age_plugin_ssh_agent::crypto::AgeIdentity;
use age_plugin_ssh_agent::plugin;
use chrono::{DateTime, Local, SecondsFormat};
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
        help = "identity to use for keypair generation (SHA256 fingerprint or fingerprint)",
        long
    )]
    identity: Option<String>,
    #[arg(
        help = "use an additional salt for each encryption for added security (requires agent presence / approval for encryption)",
        long
    )]
    extra_salt: bool,
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

    let agent_socket = args.agent_socket.as_deref().unwrap_or_else(|| {
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
    let mut store = IdentityStore::new(Client::new(stream));

    if args.list_identities {
        match format_identities(&mut store) {
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

        let identity_file =
            match generate_identity(&mut store, &args.identity.unwrap(), args.extra_salt) {
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
        run_state_machine(&state_machine, plugin::Handler)?;
        return Ok(());
    }

    // Here you can assume the binary is being run directly by a user,
    // and perform administrative tasks like generating keys.

    Ok(())
}

fn format_identities(store: &mut UnixIdentityStore) -> Result<String, Box<dyn Error>> {
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
    created: DateTime<Local>,
    recipient: String,
    identity: String,
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

fn generate_identity(
    store: &mut UnixIdentityStore,
    identity: &str,
    extra_salt: bool,
) -> Result<AgeIdentityFile, Box<dyn Error>> {
    let credential = store.find(identity)?.credential.clone();
    let (stored_identity, recipient) = AgeIdentity::new(store, &credential, extra_salt)?;

    Ok(AgeIdentityFile {
        created: Local::now(),
        recipient,
        identity: stored_identity.to_string(),
    })
}

fn write_identity(new_identity: &AgeIdentityFile, output: Option<&str>) -> io::Result<()> {
    let Some(path) = output else {
        println!("{new_identity}");
        return Ok(());
    };

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
