#![allow(dead_code)]

use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;

use sha2::Digest;
use ssh_agent_lib::proto::Identity;
use ssh_agent_lib::proto::message::PublicCredential;
use ssh_agent_lib::ssh_key::HashAlg::Sha256;
use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
use zeroize::Zeroizing;

use age_plugin_ssh_agent::agent::{AgentClient, SIGNATURE_LEN};
use age_plugin_ssh_agent::identity::Identity as AgeIdentity;

// SHA-512 is conveniently the same length as an Ed25519 signature. Hashing the key's raw
// SHA-256 fingerprint in binds it to the key, so signing with the wrong key fails decryption.
pub fn deterministic_signature(credential: &PublicCredential, data: &[u8]) -> [u8; SIGNATURE_LEN] {
    let fingerprint = credential.key_data().fingerprint(Sha256);
    sha2::Sha512::digest([fingerprint.as_bytes(), data].concat()).into()
}

/// How `MockAgent::sign` responds.
#[derive(Clone, Debug, Default)]
pub enum SignMode {
    /// SHA-512 of the key fingerprint and data.
    #[default]
    Deterministic,
    /// Last byte replaced by the call count, so repeated signatures differ.
    Varying,
    /// Every sign call errors with this message.
    Failing(String),
    /// The first `n` sign calls succeed; later ones error with this message.
    FailAfter(usize, String),
}

/// A recorded sign request.
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

/// In-memory [`AgentClient`]. Clones share state, so a test can inspect calls after handing
/// one to `Agent`.
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

        let mut signature = deterministic_signature(credential, data);
        match &state.sign_mode {
            SignMode::Deterministic => {}
            SignMode::Varying => signature[SIGNATURE_LEN - 1] = call as u8,
            SignMode::Failing(message) => return Err(message.clone().into()),
            SignMode::FailAfter(n, message) if call >= *n => return Err(message.clone().into()),
            SignMode::FailAfter(..) => {}
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

/// FIDO sk-ed25519 identity; `Agent::identities` filters it out.
pub fn sk_ed25519_identity(byte: u8, comment: &str) -> Identity {
    Identity {
        credential: PublicCredential::Key(KeyData::SkEd25519(SkEd25519::new(
            Ed25519PublicKey([byte; 32]),
            "ssh:",
        ))),
        comment: comment.to_owned(),
    }
}

// identity for key [1; 32] with salt [0, 1, .., 31], as pinned in src/identity.rs
pub const KAT_IDENTITY: &str = "AGE-PLUGIN-SSH-AGENT-1V9NK2TTSD36KW6TW94EHX6PDV9NK2MN59AMRZ3TEH7HWVARE8NG4ETPZ6SZQGREFC8G4SP6RV6W0FG7JZHTL7CNSQQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SA78MTJ";
// derived outside this crate (python HKDF-SHA256 + X25519 + bech32) from the MockAgent
// signature of KAT_IDENTITY: SHA-512(fingerprint([1; 32]) ‖ NAMESPACE ‖ [0, 1, .., 31])
pub const KAT_RECIPIENT: &str = "age128dk9r3lt6wg8uuv3hp93q86fklrxpmkseccxmf7x8u74mwguszqa6pwv3";

/// Decodes a bech32 string of any length (the `bech32` crate rejects over 90 characters).
pub fn bech32_payload(encoded: &str) -> Vec<u8> {
    age_core::primitives::bech32_decode(
        encoded,
        |e| format!("invalid bech32: {e}"),
        |_| Ok(()),
        |_, bytes| Ok(bytes.collect()),
    )
    .unwrap()
}

/// [`KAT_IDENTITY`], parsed.
pub fn kat_identity() -> AgeIdentity {
    AgeIdentity::from_bytes(&bech32_payload(KAT_IDENTITY)).unwrap()
}

/// The bytes age hands the plugin: the identity's bech32 payload.
pub fn identity_bytes(identity: &AgeIdentity) -> Vec<u8> {
    bech32_payload(&identity.to_string())
}

/// The salt is the tail of the identity's bech32 payload.
pub fn salt_of(identity: &AgeIdentity) -> Vec<u8> {
    let payload = identity_bytes(identity);
    payload[payload.len() - 32..].to_vec()
}
