#![allow(dead_code)]

use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;

use sha2::Digest;
use ssh_agent_lib::proto::Identity;
use ssh_agent_lib::proto::message::PublicCredential;
use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
use zeroize::Zeroizing;

use age_plugin_ssh_agent::agent::{AgentClient, SIGNATURE_LEN};
use age_plugin_ssh_agent::identity::Identity as AgeIdentity;

// SHA-512 is conveniently the same length as an Ed25519 signature
pub fn deterministic_signature(data: &[u8]) -> [u8; SIGNATURE_LEN] {
    sha2::Sha512::digest(data).into()
}

#[derive(Clone, Debug, Default)]
pub enum SignMode {
    #[default]
    Deterministic,
    Varying,
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

impl AgentClient for MockAgent {
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
        credential: &PublicCredential,
        data: &[u8],
    ) -> Result<Zeroizing<[u8; SIGNATURE_LEN]>, Box<dyn Error>> {
        let mut state = self.state.borrow_mut();
        let call = state.sign_calls.len();
        state.sign_calls.push(SignCall {
            credential: credential.clone(),
            data: data.to_vec(),
        });

        let mut signature = deterministic_signature(data);
        match &state.sign_mode {
            SignMode::Deterministic => {}
            SignMode::Varying => signature[SIGNATURE_LEN - 1] = call as u8,
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

/// The salt is the tail of the identity's bech32 payload.
pub fn salt_of(identity: &AgeIdentity) -> Vec<u8> {
    let (_, payload) = age_core::primitives::bech32_decode(
        &identity.to_string(),
        |e| format!("invalid bech32: {e}"),
        |_| Ok(()),
        |hrp, bytes| Ok((hrp, bytes.collect::<Vec<u8>>())),
    )
    .unwrap();
    payload[payload.len() - 32..].to_vec()
}
