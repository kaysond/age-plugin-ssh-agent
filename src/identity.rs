use rand::TryRng;

use std::error::Error;
use std::fmt;

use crate::agent::{Agent, AgentClient, FINGERPRINT_LEN};
use crate::crypto::{NAMESPACE, derive_wrapping_key, derive_x25519_secret, sign_identity};
use age_core::format::{FILE_KEY_BYTES, FileKey, Stanza};
use age_core::primitives::{aead_decrypt, aead_encrypt, bech32_encode};
use age_core::secrecy::ExposeSecret;
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use bech32::Hrp;
use rand::rngs::SysRng;
use ssh_agent_lib::proto::Identity as AgentIdentity;
use ssh_agent_lib::ssh_key::HashAlg;
use zeroize::Zeroizing;

const SALT_LEN: usize = 32;
pub const STANZA_TAG: &str = "ssh-agent";

#[derive(Debug)]
pub struct Identity {
    fingerprint: [u8; FINGERPRINT_LEN],
    pub(crate) salt: Zeroizing<[u8; SALT_LEN]>,
}

impl Identity {
    pub fn new(agent_identity: &AgentIdentity) -> Result<Self, Box<dyn Error>> {
        let fingerprint: [u8; FINGERPRINT_LEN] = agent_identity
            .credential
            .key_data()
            .fingerprint(HashAlg::Sha256)
            .sha256()
            .expect("fingerprint was not SHA256");
        let mut salt = Zeroizing::new([0u8; SALT_LEN]);
        SysRng.try_fill_bytes(salt.as_mut_slice())?;

        Ok(Identity { fingerprint, salt })
    }

    pub fn age_identity<A: AgentClient>(
        &self,
        agent: &mut Agent<A>,
    ) -> Result<age::x25519::Identity, Box<dyn Error>> {
        let agent_identity = agent.find_bytes(&self.fingerprint)?.clone();
        let signature = sign_identity(self, agent, &agent_identity, None)?;
        let secret = derive_x25519_secret(signature.as_slice())?;

        // age only constructs an Identity from its string encoding
        let encoded = Zeroizing::new(bech32_encode(
            Hrp::parse_unchecked("AGE-SECRET-KEY-"),
            secret.as_bytes(),
        ));
        Ok(Zeroizing::new(encoded.to_uppercase()).parse()?)
    }

    pub fn age_recipient<A: AgentClient>(
        &self,
        agent: &mut Agent<A>,
    ) -> Result<age::x25519::Recipient, Box<dyn Error>> {
        Ok(self.age_identity(agent)?.to_public())
    }

    fn wrapping_key<A: AgentClient>(
        &self,
        agent: &mut Agent<A>,
        file_salt: [u8; SALT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
        let agent_identity = agent.find_bytes(&self.fingerprint)?.clone();
        let signature = sign_identity(self, agent, &agent_identity, Some(file_salt))?;
        derive_wrapping_key(signature.as_slice())
    }

    pub fn wrap_file_key<A: AgentClient>(
        &self,
        agent: &mut Agent<A>,
        file_key: &FileKey,
    ) -> Result<Stanza, Box<dyn Error>> {
        let mut file_salt = [0u8; SALT_LEN];
        SysRng.try_fill_bytes(&mut file_salt)?;
        let key = self.wrapping_key(agent, file_salt)?;
        Ok(Stanza {
            tag: STANZA_TAG.into(),
            args: vec![BASE64_STANDARD_NO_PAD.encode(file_salt)],
            // zero nonce is safe: the random file salt makes every key single-use
            body: aead_encrypt(&key, file_key.expose_secret()),
        })
    }

    pub fn unwrap_stanza<A: AgentClient>(
        &self,
        agent: &mut Agent<A>,
        stanza: &Stanza,
    ) -> Option<Result<FileKey, Box<dyn Error>>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        let file_salt = match &stanza.args[..] {
            [arg] => BASE64_STANDARD_NO_PAD
                .decode(arg)
                .ok()
                .and_then(|salt| <[u8; SALT_LEN]>::try_from(salt).ok()),
            _ => None,
        };
        let Some(file_salt) = file_salt else {
            return Some(Err("invalid ssh-agent stanza arguments".into()));
        };
        if stanza.body.len() != FILE_KEY_BYTES + 16 {
            return Some(Err("invalid ssh-agent stanza body".into()));
        }
        let key = match self.wrapping_key(agent, file_salt) {
            Ok(key) => key,
            Err(e) => return Some(Err(e)),
        };
        // a failed decryption means another identity wrapped this stanza
        let plaintext = Zeroizing::new(aead_decrypt(&key, FILE_KEY_BYTES, &stanza.body).ok()?);
        Some(Ok(FileKey::init_with_mut(|file_key| {
            file_key.copy_from_slice(&plaintext)
        })))
    }

    fn to_bytes(&self) -> Zeroizing<[u8; NAMESPACE.len() + FINGERPRINT_LEN + SALT_LEN]> {
        let mut bytes = Zeroizing::new([0u8; NAMESPACE.len() + FINGERPRINT_LEN + SALT_LEN]);
        let (namespace, rest) = bytes.split_at_mut(NAMESPACE.len());
        let (fingerprint, salt) = rest.split_at_mut(FINGERPRINT_LEN);
        namespace.copy_from_slice(NAMESPACE);
        fingerprint.copy_from_slice(&self.fingerprint);
        salt.copy_from_slice(self.salt.as_slice());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        if bytes.len() != NAMESPACE.len() + FINGERPRINT_LEN + SALT_LEN {
            return Err("invalid identity".into());
        }
        let (namespace, rest) = bytes.split_at(NAMESPACE.len());
        let (fingerprint, salt) = rest.split_at(FINGERPRINT_LEN);
        if namespace != NAMESPACE {
            return Err("invalid identity".into());
        }
        Ok(Identity {
            fingerprint: fingerprint.try_into()?,
            salt: Zeroizing::new(salt.try_into()?),
        })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse_unchecked("age-plugin-ssh-agent-");
        write!(
            f,
            "{}",
            bech32_encode(hrp, self.to_bytes().as_slice()).to_uppercase()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // derived outside this crate (python SHA-256 + bech32) from the all-ones Ed25519 key and
    // SALT = [0, 1, .., 31]. These must never change without a version bump or existing identities break.
    const IDENTITY: &str = "AGE-PLUGIN-SSH-AGENT-1V9NK2TTSD36KW6TW94EHX6PDV9NK2MN59AMRZ3TEH7HWVARE8NG4ETPZ6SZQGREFC8G4SP6RV6W0FG7JZHTL7CNSQQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0SA78MTJ";

    fn salt() -> [u8; SALT_LEN] {
        std::array::from_fn(|i| i as u8)
    }

    fn identity() -> Identity {
        use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData};
        Identity {
            fingerprint: KeyData::Ed25519(Ed25519PublicKey([1; 32]))
                .fingerprint(HashAlg::Sha256)
                .sha256()
                .unwrap(),
            salt: Zeroizing::new(salt()),
        }
    }

    #[test]
    fn displays_expected_identity() {
        assert_eq!(identity().to_string(), IDENTITY);
    }

    #[test]
    fn display_round_trips() {
        let identity = identity();

        // age_core's decoder, not bech32's: the latter rejects anything over 90 characters
        let (hrp, payload) = age_core::primitives::bech32_decode(
            &identity.to_string(),
            |e| format!("invalid bech32: {e}"),
            |_| Ok(()),
            |hrp, bytes| Ok((hrp, bytes.collect::<Vec<u8>>())),
        )
        .unwrap();

        assert_eq!(hrp.as_str(), "AGE-PLUGIN-SSH-AGENT-");
        assert_eq!(payload, identity.to_bytes().as_slice());
        let (namespace, rest) = payload.split_at(NAMESPACE.len());
        let (fingerprint, payload_salt) = rest.split_at(FINGERPRINT_LEN);
        assert_eq!(namespace, NAMESPACE);
        assert_eq!(fingerprint, identity.fingerprint);
        assert_eq!(payload_salt, salt());
    }
}
