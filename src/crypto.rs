use age_core::primitives::bech32_encode;
use bech32::Hrp;
use hkdf::Hkdf;
use rand::TryRng;
use rand::rngs::SysRng;
use ssh_agent_lib::proto::message::PublicCredential;
use ssh_agent_lib::ssh_key::Fingerprint;
use ssh_agent_lib::ssh_key::HashAlg::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use std::error::Error;
use std::fmt;
use std::mem;

use crate::agent::{IdentityStore, SshAgent};

const V1: &[u8] = b"age-plugin-ssh-agent/v1";
const HKDF_SALT: &[u8] = b"age-plugin-ssh-agent/v1/hkdf-salt";
const HKDF_INFO: &[u8] = b"age-plugin-ssh-agent/v1/X25519";

const RECIPIENT_HRP: Hrp = Hrp::parse_unchecked("age");
const IDENTITY_HRP: Hrp = Hrp::parse_unchecked("age-plugin-ssh-agent-");

pub struct AgeIdentity {
    fingerprint: Fingerprint,
    salt: [u8; 16],
}

impl AgeIdentity {
    pub fn new<A: SshAgent>(
        store: &mut IdentityStore<A>,
        credential: &PublicCredential,
    ) -> Result<(Self, String), Box<dyn Error>> {
        let mut salt = [0u8; 16];
        SysRng.try_fill_bytes(&mut salt)?;

        let identity = AgeIdentity {
            fingerprint: credential.key_data().fingerprint(Sha256),
            salt,
        };
        let signature = store.sign(credential, identity.signature_data())?;

        let mut okm = Zeroizing::new([0u8; 32]);
        // do this all at once so the PRK (::new() step) is dropped immediately
        Hkdf::<sha2::Sha256>::new(Some(HKDF_SALT), &signature)
            .expand(HKDF_INFO, okm.as_mut_slice())?;

        // use mem::take to empty okm immediately
        let secret = StaticSecret::from(mem::take(&mut *okm));
        // we have to match age here so it can encrypt with its native x25519 recipient;
        // age_core's bech32_encode because it doesn't enforce length restrictions
        let recipient = bech32_encode(RECIPIENT_HRP, PublicKey::from(&secret).as_bytes());

        Ok((identity, recipient))
    }

    fn signature_data(&self) -> Vec<u8> {
        let mut data = V1.to_vec();
        data.extend_from_slice(&self.salt);
        data
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = V1.to_vec();
        bytes.extend_from_slice(self.fingerprint.as_bytes());
        bytes.extend_from_slice(&self.salt);
        bytes
    }
}

impl fmt::Display for AgeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            bech32_encode(IDENTITY_HRP, &self.to_bytes()).to_uppercase()
        )
    }
}
