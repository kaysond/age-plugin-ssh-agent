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

// R ‖ S
const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Debug)]
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
        // the agent hands back raw signature bytes with no algorithm, so length is all we can check
        if signature.len() != ED25519_SIGNATURE_LEN {
            return Err("agent did not return an Ed25519-sized signature".into());
        }
        // we filter for ed25519 identities only, so signatures should always be the same
        // but we double check just in case because if they're not, data would be unrecoverable!!
        let signature2 = store.sign(credential, identity.signature_data())?;

        if signature != signature2 {
            return Err("agent signatures are not deterministic!".into());
        }

        let secret = derive_secret(&signature)?;
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

fn derive_secret(signature: &[u8]) -> Result<StaticSecret, Box<dyn Error>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    // do this all at once so the PRK (::new() step) is dropped immediately
    Hkdf::<sha2::Sha256>::new(Some(HKDF_SALT), signature).expand(HKDF_INFO, okm.as_mut_slice())?;

    // use mem::take to empty okm immediately
    Ok(StaticSecret::from(mem::take(&mut *okm)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData};

    const SALT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    // derived outside this crate (pure-python HKDF-SHA256 + X25519 + bech32) from SALT, the
    // all-ones Ed25519 key and a SHA-512 "signature" of V1 ‖ SALT. These must never change without
    // a version bump: a different derivation makes every already-encrypted file unrecoverable.
    const RECIPIENT: &str = "age1urcpf7856lz86d8fd304m5kqzskpsclqczlqg2qvyux5n5us4g0qzrvrp7";
    const IDENTITY: &str = "AGE-PLUGIN-SSH-AGENT-1V9NK2TTSD36KW6TW94EHX6PDV9NK2MN59AMRZ3TEH7HWVARE8NG4ETPZ6SZQGREFC8G4SP6RV6W0FG7JZHTL7CNSQQQSYQCYQ5RQWZQFPG9SCRGWPUYUD2YR";

    fn identity() -> AgeIdentity {
        AgeIdentity {
            fingerprint: KeyData::Ed25519(Ed25519PublicKey([1; 32])).fingerprint(Sha256),
            salt: SALT,
        }
    }

    // 64 bytes, so it stands in for an Ed25519 signature
    fn signature() -> Vec<u8> {
        sha2::Sha512::digest(identity().signature_data()).to_vec()
    }

    #[test]
    fn derives_expected_recipient() {
        let secret = derive_secret(&signature()).unwrap();

        assert_eq!(
            bech32_encode(RECIPIENT_HRP, PublicKey::from(&secret).as_bytes()),
            RECIPIENT
        );
    }

    #[test]
    fn displays_expected_identity() {
        assert_eq!(identity().to_string(), IDENTITY);
    }

    #[test]
    fn signature_data_is_version_and_salt() {
        assert_eq!(identity().signature_data(), [V1, &SALT[..]].concat());
    }

    #[test]
    fn derived_secret_is_usable_by_age() {
        let secret = derive_secret(&signature()).unwrap();

        let recipient: age::x25519::Recipient =
            bech32_encode(RECIPIENT_HRP, PublicKey::from(&secret).as_bytes())
                .parse()
                .expect("valid age recipient");
        let secret_key = bech32_encode(Hrp::parse_unchecked("AGE-SECRET-KEY-"), secret.as_bytes())
            .to_uppercase();
        let age_identity: age::x25519::Identity = secret_key.parse().expect("valid age identity");

        let ciphertext = age::encrypt(&recipient, b"hello").unwrap();
        assert_eq!(
            age::decrypt(&age_identity, &ciphertext).unwrap(),
            b"hello".to_vec()
        );
    }

    #[test]
    fn identity_display_round_trips() {
        let identity = identity();

        // age_core's decoder, not bech32's: the latter rejects anything over 90 characters
        let (hrp, payload) = age_core::primitives::bech32_decode(
            &identity.to_string(),
            |e| format!("invalid bech32: {e}"),
            |_| Ok(()),
            |hrp, bytes| Ok((hrp, bytes.collect::<Vec<u8>>())),
        )
        .unwrap();

        assert_eq!(hrp, IDENTITY_HRP);
        assert_eq!(payload, identity.to_bytes());
        assert_eq!(payload.len(), V1.len() + 32 + SALT.len());
        assert_eq!(&payload[..V1.len()], V1);
        assert_eq!(
            &payload[V1.len()..V1.len() + 32],
            identity.fingerprint.as_bytes()
        );
        assert_eq!(&payload[V1.len() + 32..], &SALT[..]);
    }
}
