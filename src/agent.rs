use ssh_agent_lib::blocking::Client;
use ssh_agent_lib::proto::message::PublicCredential;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_agent_lib::ssh_key::Algorithm;
use ssh_agent_lib::ssh_key::HashAlg::Sha256;
use std::error::Error;
use std::os::unix::net::UnixStream;
use zeroize::Zeroizing;

pub type UnixIdentityStore = IdentityStore<Client<UnixStream>>;

pub trait SshAgent {
    fn request_identities(&mut self) -> Result<Vec<Identity>, Box<dyn Error>>;
    fn sign(
        &mut self,
        credential: PublicCredential,
        data: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>>;
}

pub struct IdentityStore<A: SshAgent> {
    agent: A,
    identities: Vec<Identity>,
}

impl SshAgent for Client<UnixStream> {
    fn request_identities(&mut self) -> Result<Vec<Identity>, Box<dyn Error>> {
        // fully qualified so this can't silently recurse if the trait method is renamed
        Ok(Client::request_identities(self)?)
    }
    fn sign(
        &mut self,
        credential: PublicCredential,
        data: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
        let request: SignRequest = SignRequest {
            credential,
            data,
            flags: 0,
        };
        let signature = Client::sign(self, request)?;

        if signature.algorithm() != Algorithm::Ed25519 {
            return Err("agent returned non-Ed25519 signature".into());
        }
        Ok(Zeroizing::new(signature.as_bytes().to_vec()))
    }
}

impl<A: SshAgent> IdentityStore<A> {
    pub fn new(agent: A) -> Self {
        IdentityStore {
            agent,
            identities: vec![],
        }
    }

    pub fn identities(&mut self) -> Result<&[Identity], Box<dyn Error>> {
        if !self.identities.is_empty() {
            return Ok(&self.identities);
        }
        let identities: Vec<Identity> = self
            .agent
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

    pub fn find(&mut self, identity_string: &str) -> Result<&Identity, Box<dyn Error>> {
        let identities = self.identities()?;

        for identity in identities {
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
            if identity_string == fingerprint || identity_string == identity.comment {
                return Ok(identity);
            }
        }

        Err(format!("could not find identity matching '{identity_string}'").into())
    }

    pub fn sign(
        &mut self,
        credential: &PublicCredential,
        data: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
        self.agent.sign(credential.clone(), data)
    }
}
