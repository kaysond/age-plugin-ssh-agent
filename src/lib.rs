//! An [age](https://age-encryption.org) plugin that derives X25519 keys from an ssh-agent
//! Ed25519 key.
//!
//! No age secret key is stored on disk. The identity file holds only the SSH key's SHA-256
//! fingerprint and a random secret; the age key is recomputed on demand by asking the agent to
//! sign a fixed message. Ed25519 signatures are deterministic, so the same SSH key and secret always
//! give the same age key.
//!
//! # Key derivation
//!
//! ```text
//! sig      = agent.sign(key, NAMESPACE ‖ identity_secret [‖ file_salt])
//! x25519   = HKDF-SHA256(salt = "age-plugin-ssh-agent/v1/hkdf-salt", ikm = sig,
//!                        info = "age-plugin-ssh-agent/v1/X25519")
//! wrap_key = HKDF-SHA256(same salt, ikm = sig, info = "age-plugin-ssh-agent/v1/wrap")
//! ```
//!
//! [`NAMESPACE`](crypto::NAMESPACE) is `age-plugin-ssh-agent/v1`.
//!
//! * Without a file salt, the signature yields a static X25519 secret whose public key is an
//!   ordinary `age1…` recipient. Anyone can encrypt to it with stock `age`, no plugin needed.
//! * When encrypting to the plugin identity itself, each file gets a fresh 32-byte file salt.
//!   The resulting signature feeds the wrap key, which encrypts the file key into an
//!   `ssh-agent` stanza. Encrypting this way needs the agent.
//!
//! Every constant above is part of the on-disk format. Changing any of them makes existing
//! identities and files unrecoverable.
//!
//! # Security
//!
//! * Signatures, signed messages, derived keys, and the identity secret live in zeroize-on-drop
//!   buffers.
//! * Never log signatures, derived keys, or identity strings (including the `Debug` output of
//!   [`identity::Identity`]): an identity plus agent access yields the secret key.
//! * Every signature is requested twice and compared. A non-deterministic signer would make
//!   data unrecoverable, so a mismatch is an error.
//! * Only plain Ed25519 keys are used; other key types are filtered out.
//!
//! # Modules
//!
//! * [`agent`]: ssh-agent client wrapper (Ed25519 filtering, lookup, deterministic signing).
//! * [`crypto`]: signing input and HKDF derivation.
//! * [`identity`]: the plugin identity, its encoding, and stanza wrap/unwrap.
//! * [`plugin`]: the `age-plugin` state machine handlers.

pub mod agent;
pub mod crypto;
pub mod identity;
pub mod plugin;
