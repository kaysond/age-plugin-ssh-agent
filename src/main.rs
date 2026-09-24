use age_plugin::run_state_machine;
use age_plugin_ssh_agent::agent;
use age_plugin_ssh_agent::plugin;
use clap::Parser;
use ssh_agent_lib::ssh_key::HashAlg::Sha256;

use std::error::Error;
use std::io;

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

    if args.list_identities {
        let agent_socket = args.agent_socket.as_deref().unwrap_or_else(|| {
            eprintln!("no agent socket path specified and SSH_AUTH_SOCK env var isn't set");
            std::process::exit(1);
        });
        match list_identities(agent_socket) {
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

fn list_identities(agent_socket: &str) -> Result<String, Box<dyn Error>> {
    let identity_list = agent::retrieve_identities(agent_socket)?
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
