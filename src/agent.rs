use ssh_agent_lib::blocking::Client;
use ssh_agent_lib::proto::Identity;
use ssh_agent_lib::ssh_key::HashAlg::Sha256;
use std::error::Error;
use std::os::unix::net::UnixStream;

pub fn retrieve_identities(socket_path: &str) -> Result<Vec<Identity>, Box<dyn Error>> {
    let mut client = Client::new(UnixStream::connect(socket_path)?);

    let identities: Vec<Identity> = client
        .request_identities()?
        .into_iter()
        .filter(|identity| identity.credential.key_data().is_ed25519())
        .collect();

    if identities.is_empty() {
        return Err("no valid (Ed25519) identities found in the agent".into());
    }

    Ok(identities)
}

pub fn select_identity(
    socket_path: &str,
    identity_string: &str,
) -> Result<Identity, Box<dyn Error>> {
    let identities = retrieve_identities(socket_path)?;

    for identity in identities {
        if identity_string == identity.comment {
            return Ok(identity);
        }
        // it's a little ambiguous in the help whether the arg should be prefixed or not
        let identity_string = if identity_string.starts_with("SHA256:") {
            identity_string
        } else {
            &format!("SHA256:{identity_string}")
        };
        let fingerprint = identity
            .credential
            .key_data()
            .fingerprint(Sha256)
            .to_string();
        if identity_string == fingerprint {
            return Ok(identity);
        };
    }

    Err(format!("could not find identity matching '{identity_string}'").into())
}
