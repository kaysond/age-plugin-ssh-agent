//! Agent signing input and HKDF-SHA256 key derivation.
//!
//! Every constant here is part of the on-disk format: changing one changes every derived key
//! and makes existing identities and files unrecoverable.

use hkdf::Hkdf;
use sha2::Sha256;
use ssh_agent_lib::proto::Identity as AgentIdentity;
use std::error::Error;
use std::mem;
use x25519_dalek::StaticSecret;

use crate::agent::{Agent, AgentClient};

use crate::identity::Identity;
use zeroize::Zeroizing;

/// Domain separator prefixed to every message the agent signs, and to the identity encoding.
pub const NAMESPACE: &[u8] = b"age-plugin-ssh-agent/v1";
const HKDF_SALT: &[u8] = b"age-plugin-ssh-agent/v1/hkdf-salt";
const HKDF_X25519_INFO: &[u8] = b"age-plugin-ssh-agent/v1/X25519";
const HKDF_WRAP_INFO: &[u8] = b"age-plugin-ssh-agent/v1/wrap";

/// Asks the agent to sign `NAMESPACE ‖ identity.secret [‖ file_salt]` with `agent_identity`.
///
/// `file_salt` is the per-file salt used for `ssh-agent` stanzas; `None` gives the signature behind
/// the static X25519 identity. The returned signature is the HKDF input key material: it is
/// secret and is zeroized on drop.
///
/// Errors if the agent fails to sign or its signatures are not deterministic (see
/// [`Agent::sign`]).
pub fn sign_identity<A: AgentClient>(
    identity: &Identity,
    agent: &mut Agent<A>,
    agent_identity: &AgentIdentity,
    file_salt: Option<[u8; 32]>,
) -> Result<Zeroizing<[u8; 64]>, Box<dyn Error>> {
    let data = Zeroizing::new(
        [
            NAMESPACE,
            identity.secret.as_slice(),
            file_salt.as_slice().as_flattened(),
        ]
        .concat(),
    );
    agent.sign(agent_identity, &data)
}

fn expand(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    // do this all at once so the PRK (::new() step) is dropped immediately
    Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm).expand(info, okm.as_mut_slice())?;
    Ok(okm)
}

/// Derives the static X25519 secret from an agent signature.
///
/// The returned [`StaticSecret`] is the age secret key. It is zeroized on drop; never log or
/// persist it.
///
/// HKDF expansion cannot fail for a 32-byte output, so errors are not expected in practice.
pub fn derive_x25519_secret(ikm: &[u8]) -> Result<StaticSecret, Box<dyn Error>> {
    // use mem::take to zero okm immediately
    Ok(StaticSecret::from(mem::take(&mut *expand(
        ikm,
        HKDF_X25519_INFO,
    )?)))
}

/// Derives the ChaCha20-Poly1305 key that wraps a file key in an `ssh-agent` stanza.
///
/// `ikm` must be a signature that included a fresh per-file salt; the key is used with a
/// zero nonce, so it must never wrap more than one file key.
///
/// HKDF expansion cannot fail for a 32-byte output, so errors are not expected in practice.
pub fn derive_wrapping_key(ikm: &[u8]) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
    expand(ikm, HKDF_WRAP_INFO)
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
    // derived the same way (python HKDF-SHA256) with the wrap label; same stability rule applies
    const WRAP_KEY: &str = "5436bf00e0c8482e7f2e5e6af11adae755b458764c50a6e1bf670af66141da43";

    // 64 bytes, so it stands in for an Ed25519 signature
    fn signature() -> Vec<u8> {
        let secret: Vec<u8> = (0..32).collect();
        Sha512::digest([NAMESPACE, &secret].concat()).to_vec()
    }

    fn recipient(secret: &StaticSecret) -> String {
        bech32_encode(
            Hrp::parse_unchecked("age"),
            PublicKey::from(secret).as_bytes(),
        )
    }

    #[test]
    fn derives_expected_recipient() {
        assert_eq!(
            recipient(&derive_x25519_secret(&signature()).unwrap()),
            RECIPIENT
        );
    }

    #[test]
    fn derives_expected_wrap_key() {
        let key = derive_wrapping_key(&signature()).unwrap();
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, WRAP_KEY);
    }

    #[test]
    fn derived_secret_is_usable_by_age() {
        let secret = derive_x25519_secret(&signature()).unwrap();

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
