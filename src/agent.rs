//! Thin wrapper around an ssh-agent connection.
//!
//! Only plain Ed25519 keys are exposed, since key derivation needs deterministic signatures.

use ssh_agent_lib::blocking::Client;
use ssh_agent_lib::proto::message::PublicCredential;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_agent_lib::ssh_key::HashAlg::Sha256;
use std::error::Error;
use std::os::unix::net::UnixStream;
use zeroize::Zeroizing;

/// [`Agent`] over a Unix socket connection, as used by the binary.
pub type UnixStreamAgent = Agent<Client<UnixStream>>;

/// Length of a raw SHA-256 key fingerprint.
pub const FINGERPRINT_LEN: usize = 32; // SHA256
/// Length of an Ed25519 signature (`R ‖ S`).
pub const SIGNATURE_LEN: usize = 64;

/// Minimal ssh-agent operations, so tests can substitute a mock agent.
pub trait AgentClient {
    /// Lists every key the agent holds, unfiltered.
    fn request_identities(&mut self) -> Result<Vec<Identity>, Box<dyn Error>>;
    /// Signs `data` with `credential` and returns the raw signature bytes.
    ///
    /// Errors if the agent refuses or returns a signature that is not
    /// [`SIGNATURE_LEN`] bytes. The signature is key material: keep it in [`Zeroizing`] and
    /// never log it.
    fn sign(
        &mut self,
        credential: &PublicCredential,
        data: &[u8],
    ) -> Result<Zeroizing<[u8; SIGNATURE_LEN]>, Box<dyn Error>>;
}

/// ssh-agent client that caches the agent's Ed25519 keys.
///
/// The key list is fetched once, on first use, and never refreshed.
pub struct Agent<A: AgentClient> {
    client: A,
    identities: Vec<Identity>,
}

impl AgentClient for Client<UnixStream> {
    fn request_identities(&mut self) -> Result<Vec<Identity>, Box<dyn Error>> {
        Ok(Client::request_identities(self)?)
    }
    fn sign(
        &mut self,
        credential: &PublicCredential,
        data: &[u8],
    ) -> Result<Zeroizing<[u8; SIGNATURE_LEN]>, Box<dyn Error>> {
        let request: SignRequest = SignRequest {
            credential: credential.clone(),
            data: data.to_vec(),
            flags: 0,
        };

        let sig: Zeroizing<[u8; SIGNATURE_LEN]> = Zeroizing::new(
            Client::sign(self, request)?
                .as_bytes()
                .try_into()
                .map_err(|_| "agent returned a signature with the wrong size")?,
        );
        Ok(sig)
    }
}

impl<A: AgentClient> Agent<A> {
    /// Wraps `client`. Does not contact the agent.
    pub fn new(client: A) -> Self {
        Agent {
            client,
            identities: vec![],
        }
    }

    /// Returns the agent's plain Ed25519 keys (FIDO `sk-ssh-ed25519` keys excluded).
    ///
    /// Errors if the agent request fails or no Ed25519 key is loaded.
    pub fn identities(&mut self) -> Result<&[Identity], Box<dyn Error>> {
        if !self.identities.is_empty() {
            return Ok(&self.identities);
        }
        let identities: Vec<Identity> = self
            .client
            .request_identities()?
            .into_iter()
            .filter(|identity| identity.credential.key_data().is_ed25519())
            .collect();

        if identities.is_empty() {
            return Err("no valid (Ed25519) identities found in the agent".into());
        }
        self.identities = identities;

        Ok(&self.identities)
    }

    /// Finds a key by comment or by SHA-256 fingerprint, with or without the `SHA256:` prefix.
    ///
    /// Errors if no Ed25519 key matches.
    pub fn find(&mut self, identity_string: &str) -> Result<&Identity, Box<dyn Error>> {
        let identities = self.identities()?;

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
            }
        }

        Err(format!("could not find identity matching '{identity_string}'").into())
    }

    /// Finds a key by its raw SHA-256 fingerprint, as stored in an
    /// [`Identity`](crate::identity::Identity).
    ///
    /// Errors if no Ed25519 key matches, e.g. the key was removed from the agent.
    pub fn find_bytes(
        &mut self,
        bytes: &[u8; FINGERPRINT_LEN],
    ) -> Result<&Identity, Box<dyn Error>> {
        let identities = self.identities()?;

        for identity in identities {
            if *bytes
                == identity
                    .credential
                    .key_data()
                    .fingerprint(Sha256)
                    .sha256()
                    .expect("fingerprint was not sha256")
            {
                return Ok(identity);
            }
        }
        Err("could not find matching identity".into())
    }

    /// Signs `data` with `identity`'s key, twice, and errors unless both signatures match.
    ///
    /// The derived secrets depend on signatures being reproducible, so a non-deterministic
    /// signature is rejected rather than used. Each call costs two agent sign requests (and
    /// two confirmation prompts for keys added with `ssh-add -c`).
    pub fn sign(
        &mut self,
        identity: &Identity,
        data: &[u8],
    ) -> Result<Zeroizing<[u8; SIGNATURE_LEN]>, Box<dyn Error>> {
        let signature = self.client.sign(&identity.credential, data)?;
        // ed25519 (which we filter for) should always result in the same signature
        // other identity types, though, don't. just in case there's an implementation
        // issue, we double check determinism of the signature. we pay the cost of doing
        // this every single time because the alternative is data becoming totally unrecoverable
        let signature2 = self.client.sign(&identity.credential, data)?;

        if signature != signature2 {
            return Err("agent signatures are not deterministic!".into());
        }
        Ok(signature)
    }
}
