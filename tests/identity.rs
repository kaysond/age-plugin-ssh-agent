mod common;

use age_plugin_ssh_agent::agent::Agent;
use age_plugin_ssh_agent::crypto::{NAMESPACE, derive_x25519_secret};
use age_plugin_ssh_agent::identity::Identity;
use common::{MockAgent, SignMode, deterministic_signature, ed25519_identity, salt_of};
use x25519_dalek::PublicKey;

#[test]
fn new_uses_a_random_salt() {
    let agent_identity = ed25519_identity(1, "laptop");
    let mut store = Agent::new(MockAgent::new(vec![agent_identity.clone()]));

    let first = Identity::new(&agent_identity).unwrap();
    let second = Identity::new(&agent_identity).unwrap();

    assert_ne!(salt_of(&first), salt_of(&second));
    assert_ne!(
        first.age_recipient(&mut store).unwrap(),
        second.age_recipient(&mut store).unwrap()
    );
}

#[test]
fn recipient_derives_from_the_agent_signature() {
    let mut store = Agent::new(MockAgent::new(vec![
        ed25519_identity(2, "desktop"),
        ed25519_identity(1, "laptop"),
    ]));
    let identity = Identity::new(&ed25519_identity(1, "laptop")).unwrap();

    let recipient = identity.age_recipient(&mut store).unwrap();

    let signature = deterministic_signature(&[NAMESPACE, &salt_of(&identity)].concat());
    let public_key = PublicKey::from(&derive_x25519_secret(&signature).unwrap());
    assert_eq!(
        recipient.to_string(),
        age_core::primitives::bech32_encode(
            bech32::Hrp::parse_unchecked("age"),
            public_key.as_bytes()
        )
    );
}

#[test]
fn recipient_signs_with_the_matching_key() {
    let agent = MockAgent::new(vec![
        ed25519_identity(2, "desktop"),
        ed25519_identity(1, "laptop"),
    ]);
    let mut store = Agent::new(agent.clone());
    let laptop = ed25519_identity(1, "laptop");
    let identity = Identity::new(&laptop).unwrap();

    identity.age_recipient(&mut store).unwrap();

    assert_eq!(agent.sign_calls()[0].credential, laptop.credential);
}

#[test]
fn recipient_errors_when_key_is_not_in_agent() {
    let mut store = Agent::new(MockAgent::new(vec![ed25519_identity(2, "desktop")]));
    let identity = Identity::new(&ed25519_identity(1, "laptop")).unwrap();

    assert_eq!(
        identity.age_recipient(&mut store).unwrap_err().to_string(),
        "could not find matching identity"
    );
}

#[test]
fn recipient_rejects_nondeterministic_signatures() {
    let mut store = Agent::new(
        MockAgent::new(vec![ed25519_identity(1, "laptop")]).with_sign_mode(SignMode::Varying),
    );
    let identity = Identity::new(&ed25519_identity(1, "laptop")).unwrap();

    assert_eq!(
        identity.age_recipient(&mut store).unwrap_err().to_string(),
        "agent signatures are not deterministic!"
    );
}
