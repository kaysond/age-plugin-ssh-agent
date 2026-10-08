use rand::TryRng;

use std::error::Error;
use std::fmt;

use crate::agent::{Agent, AgentClient, FINGERPRINT_LEN};
use crate::crypto::{NAMESPACE, derive_secret, sign_identity};
use age_core::primitives::bech32_encode;
use bech32::Hrp;
use rand::rngs::SysRng;
use ssh_agent_lib::proto::Identity as AgentIdentity;
use ssh_agent_lib::ssh_key::HashAlg;
use zeroize::Zeroizing;

const SALT_LEN: usize = 32;

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
        let secret = derive_secret(signature.as_slice())?;

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
