#![allow(dead_code)]

use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;

use sha2::Digest;
use ssh_agent_lib::proto::Identity;
use ssh_agent_lib::proto::message::PublicCredential;
use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
use zeroize::Zeroizing;

use age_plugin_ssh_agent::agent::SshAgent;

// SHA-512 is conveniently the same length as an Ed25519 signature
pub fn deterministic_signature(data: &[u8]) -> Vec<u8> {
    sha2::Sha512::digest(data).to_vec()
}

#[derive(Clone, Debug, Default)]
pub enum SignMode {
    #[default]
    Deterministic,
    Varying,
    WrongLength,
    Failing(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignCall {
    pub credential: PublicCredential,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
struct MockState {
    identities: Vec<Identity>,
    identities_error: Option<String>,
    sign_mode: SignMode,
    request_identities_calls: usize,
    sign_calls: Vec<SignCall>,
}

#[derive(Clone, Debug, Default)]
pub struct MockAgent {
    state: Rc<RefCell<MockState>>,
}

/// mock Agent we can seed with any Identities
impl MockAgent {
    pub fn new(identities: Vec<Identity>) -> Self {
        let agent = Self::default();
        agent.state.borrow_mut().identities = identities;
        agent
    }

    pub fn failing_identities(message: &str) -> Self {
        let agent = Self::default();
        agent.state.borrow_mut().identities_error = Some(message.to_owned());
        agent
    }

    pub fn with_sign_mode(self, mode: SignMode) -> Self {
        self.state.borrow_mut().sign_mode = mode;
        self
    }

    pub fn request_identities_calls(&self) -> usize {
        self.state.borrow().request_identities_calls
    }

    pub fn sign_calls(&self) -> Vec<SignCall> {
        self.state.borrow().sign_calls.clone()
    }
}

impl SshAgent for MockAgent {
    fn request_identities(&mut self) -> Result<Vec<Identity>, Box<dyn Error>> {
        let mut state = self.state.borrow_mut();
        state.request_identities_calls += 1;
        if let Some(message) = &state.identities_error {
            return Err(message.clone().into());
        }
        Ok(state.identities.clone())
    }

    fn sign(
        &mut self,
        credential: PublicCredential,
        data: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
        let mut state = self.state.borrow_mut();
        let call = state.sign_calls.len();
        state.sign_calls.push(SignCall {
            credential,
            data: data.clone(),
        });

        let mut signature = deterministic_signature(&data);
        match &state.sign_mode {
            SignMode::Deterministic => {}
            SignMode::Varying => *signature.last_mut().expect("non-empty") = call as u8,
            SignMode::WrongLength => signature.truncate(32),
            SignMode::Failing(message) => return Err(message.clone().into()),
        }
        Ok(Zeroizing::new(signature))
    }
}

pub fn ed25519_credential(byte: u8) -> PublicCredential {
    PublicCredential::Key(KeyData::Ed25519(Ed25519PublicKey([byte; 32])))
}

/// ed25519 identity whose key bytes are all `byte`
pub fn ed25519_identity(byte: u8, comment: &str) -> Identity {
    Identity {
        credential: ed25519_credential(byte),
        comment: comment.to_owned(),
    }
}

pub fn sk_ed25519_identity(byte: u8, comment: &str) -> Identity {
    Identity {
        credential: PublicCredential::Key(KeyData::SkEd25519(SkEd25519::new(
            Ed25519PublicKey([byte; 32]),
            "ssh:",
        ))),
        comment: comment.to_owned(),
    }
}
