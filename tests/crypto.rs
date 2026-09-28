mod common;

use age_plugin_ssh_agent::agent::IdentityStore;
use age_plugin_ssh_agent::crypto::AgeIdentity;
use common::{MockAgent, SignMode, ed25519_credential};

fn store_with(mode: SignMode) -> (MockAgent, IdentityStore<MockAgent>) {
    let agent = MockAgent::new(vec![]).with_sign_mode(mode);
    (agent.clone(), IdentityStore::new(agent))
}

/// The salt is the tail of the identity's bech32 payload.
fn salt_of(identity: &AgeIdentity) -> Vec<u8> {
    let (_, payload) = age_core::primitives::bech32_decode(
        &identity.to_string(),
        |e| format!("invalid bech32: {e}"),
        |_| Ok(()),
        |hrp, bytes| Ok((hrp, bytes.collect::<Vec<u8>>())),
    )
    .unwrap();
    payload[payload.len() - 16..].to_vec()
}

#[test]
fn new_signs_the_same_data_twice() {
    let (agent, mut store) = store_with(SignMode::Deterministic);
    let credential = ed25519_credential(1);

    let (identity, _) = AgeIdentity::new(&mut store, &credential).unwrap();

    let calls = agent.sign_calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    assert_eq!(calls[0].credential, credential);
    assert_eq!(
        calls[0].data,
        [&b"age-plugin-ssh-agent/v1"[..], &salt_of(&identity)].concat()
    );
}

#[test]
fn new_returns_an_age_recipient() {
    let (_agent, mut store) = store_with(SignMode::Deterministic);

    let (_, recipient) = AgeIdentity::new(&mut store, &ed25519_credential(1)).unwrap();

    let parsed: age::x25519::Recipient = recipient.parse().expect("valid age recipient");
    assert_eq!(parsed.to_string(), recipient);
}

#[test]
fn new_rejects_nondeterministic_signatures() {
    let (agent, mut store) = store_with(SignMode::Varying);

    assert_eq!(
        AgeIdentity::new(&mut store, &ed25519_credential(1))
            .unwrap_err()
            .to_string(),
        "agent signatures are not deterministic!"
    );
    assert_eq!(agent.sign_calls().len(), 2);
}

#[test]
fn new_rejects_wrong_length_signatures() {
    let (agent, mut store) = store_with(SignMode::WrongLength);

    assert_eq!(
        AgeIdentity::new(&mut store, &ed25519_credential(1))
            .unwrap_err()
            .to_string(),
        "agent did not return an Ed25519-sized signature"
    );
    // it bails before asking the agent again
    assert_eq!(agent.sign_calls().len(), 1);
}

#[test]
fn new_propagates_sign_errors() {
    let (agent, mut store) = store_with(SignMode::Failing("agent refused".into()));

    assert_eq!(
        AgeIdentity::new(&mut store, &ed25519_credential(1))
            .unwrap_err()
            .to_string(),
        "agent refused"
    );
    assert_eq!(agent.sign_calls().len(), 1);
}

#[test]
fn new_uses_a_random_salt() {
    let (agent, mut store) = store_with(SignMode::Deterministic);
    let credential = ed25519_credential(1);

    let (_, first) = AgeIdentity::new(&mut store, &credential).unwrap();
    let (_, second) = AgeIdentity::new(&mut store, &credential).unwrap();

    assert_ne!(first, second);
    let calls = agent.sign_calls();
    assert_ne!(calls[0].data, calls[2].data);
}
