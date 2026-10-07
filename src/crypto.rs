use hkdf::Hkdf;
use sha2::Sha256;
use ssh_agent_lib::proto::Identity as AgentIdentity;
use std::error::Error;
use std::mem;
use x25519_dalek::StaticSecret;

use crate::agent::{Agent, AgentClient};

use crate::identity::Identity;
use zeroize::Zeroizing;

pub const NAMESPACE: &[u8] = b"age-plugin-ssh-agent/v1";
const HKDF_SALT: &[u8] = b"age-plugin-ssh-agent/v1/hkdf-salt";
const HKDF_INFO: &[u8] = b"age-plugin-ssh-agent/v1/X25519";

pub fn sign_identity<A: AgentClient>(
    identity: &Identity,
    agent: &mut Agent<A>,
    agent_identity: &AgentIdentity,
    salt: Option<[u8; 32]>,
) -> Result<Zeroizing<[u8; 64]>, Box<dyn Error>> {
    let data = Zeroizing::new(
        [
            NAMESPACE,
            identity.salt.as_slice(),
            salt.as_slice().as_flattened(),
        ]
        .concat(),
    );
    agent.sign(agent_identity, &data)
}

pub fn derive_secret(ikm: &[u8]) -> Result<StaticSecret, Box<dyn Error>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    // do this all at once so the PRK (::new() step) is dropped immediately
    Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm).expand(HKDF_INFO, okm.as_mut_slice())?;

    // use mem::take to zero okm immediately
    Ok(StaticSecret::from(mem::take(&mut *okm)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age_core::primitives::bech32_encode;
    use bech32::Hrp;
    use sha2::{Digest, Sha512};
    use x25519_dalek::PublicKey;

    // derived outside this crate (python HKDF-SHA256 + X25519 + bech32) from a SHA-512
    // "signature" of NAMESPACE ‖ [0, 1, .., 31]. This must never change without a version bump:
    // a different derivation makes every already-encrypted file unrecoverable.
    const RECIPIENT: &str = "age1435wlpvkpldxajj8usnzjgt4daqk5wp2qj6zjf3h47llt5v9e9ssjufxna";

    // 64 bytes, so it stands in for an Ed25519 signature
    fn signature() -> Vec<u8> {
        let salt: Vec<u8> = (0..32).collect();
        Sha512::digest([NAMESPACE, &salt].concat()).to_vec()
    }

    fn recipient(secret: &StaticSecret) -> String {
        bech32_encode(
            Hrp::parse_unchecked("age"),
            PublicKey::from(secret).as_bytes(),
        )
    }

    #[test]
    fn derives_expected_recipient() {
        assert_eq!(recipient(&derive_secret(&signature()).unwrap()), RECIPIENT);
    }

    #[test]
    fn derived_secret_is_usable_by_age() {
        let secret = derive_secret(&signature()).unwrap();

        let recipient: age::x25519::Recipient =
            recipient(&secret).parse().expect("valid age recipient");
        let secret_key = bech32_encode(Hrp::parse_unchecked("AGE-SECRET-KEY-"), secret.as_bytes())
            .to_uppercase();
        let age_identity: age::x25519::Identity = secret_key.parse().expect("valid age identity");

        let ciphertext = age::encrypt(&recipient, b"hello").unwrap();
        assert_eq!(
            age::decrypt(&age_identity, &ciphertext).unwrap(),
            b"hello".to_vec()
        );
    }
}
