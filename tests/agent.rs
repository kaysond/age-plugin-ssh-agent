mod common;

use age_plugin_ssh_agent::agent::Agent;
use common::{
    MockAgent, SignMode, deterministic_signature, ed25519_credential, ed25519_identity,
    sk_ed25519_identity,
};
use ssh_agent_lib::ssh_key::HashAlg::Sha256;

// computed outside of ssh-key, so this pins the fingerprint format rather than re-deriving it:
// unpadded base64 of sha256(string("ssh-ed25519") ‖ string([1u8; 32]))
const FINGERPRINT_1: &str = "SHA256:RXm/ruZ0eTzRXKwi1AQEDynB0VgHQ2ac9KPSFdf/YnA";

fn store_with_two_keys() -> Agent<MockAgent> {
    Agent::new(MockAgent::new(vec![
        ed25519_identity(3, "desktop"),
        ed25519_identity(1, "laptop"),
        sk_ed25519_identity(2, "fido"),
    ]))
}

#[test]
fn identities_filters_non_ed25519() {
    let agent = MockAgent::new(vec![
        sk_ed25519_identity(2, "fido"),
        ed25519_identity(1, "laptop"),
        sk_ed25519_identity(9, "fido2"),
    ]);
    let mut store = Agent::new(agent);

    assert_eq!(
        store.identities().unwrap().to_vec(),
        vec![ed25519_identity(1, "laptop")]
    );
}

#[test]
fn identities_errors_when_no_ed25519() {
    let agent = MockAgent::new(vec![sk_ed25519_identity(2, "fido")]);
    let mut store = Agent::new(agent.clone());

    assert_eq!(
        store.identities().unwrap_err().to_string(),
        "no valid (Ed25519) identities found in the agent"
    );
    // the failure isn't cached, so a second call asks the agent again
    store.identities().unwrap_err();
    assert_eq!(agent.request_identities_calls(), 2);
}

#[test]
fn identities_are_cached() {
    let agent = MockAgent::new(vec![ed25519_identity(1, "laptop")]);
    let mut store = Agent::new(agent.clone());

    let first = store.identities().unwrap().to_vec();
    let second = store.identities().unwrap().to_vec();

    assert_eq!(first, second);
    assert_eq!(agent.request_identities_calls(), 1);
}

#[test]
fn identities_propagates_agent_error() {
    let mut store = Agent::new(MockAgent::failing_identities("agent is not running"));

    assert_eq!(
        store.identities().unwrap_err().to_string(),
        "agent is not running"
    );
}

#[test]
fn find_by_prefixed_fingerprint() {
    let mut store = store_with_two_keys();

    assert_eq!(store.find(FINGERPRINT_1).unwrap().comment, "laptop");
}

#[test]
fn find_by_bare_fingerprint() {
    let mut store = store_with_two_keys();
    let bare = FINGERPRINT_1.strip_prefix("SHA256:").unwrap();

    assert_eq!(store.find(bare).unwrap().comment, "laptop");
}

#[test]
fn find_by_comment() {
    let mut store = store_with_two_keys();

    assert_eq!(
        store.find("desktop").unwrap().credential,
        ed25519_credential(3)
    );
}

#[test]
fn find_errors_for_unknown() {
    let mut store = store_with_two_keys();

    assert_eq!(
        store.find("nope").unwrap_err().to_string(),
        "could not find identity matching 'nope'"
    );
}

#[test]
fn find_ignores_filtered_identities() {
    let mut store = store_with_two_keys();

    assert_eq!(
        store.find("fido").unwrap_err().to_string(),
        "could not find identity matching 'fido'"
    );
}

#[test]
fn find_bytes_by_raw_fingerprint() {
    let mut store = store_with_two_keys();
    let fingerprint = ed25519_credential(1)
        .key_data()
        .fingerprint(Sha256)
        .sha256()
        .unwrap();

    assert_eq!(store.find_bytes(&fingerprint).unwrap().comment, "laptop");
}

#[test]
fn find_bytes_errors_for_unknown() {
    let mut store = store_with_two_keys();

    assert_eq!(
        store.find_bytes(&[0; 32]).unwrap_err().to_string(),
        "could not find matching identity"
    );
}

fn signing_store(mode: SignMode) -> (MockAgent, Agent<MockAgent>) {
    let agent = MockAgent::new(vec![]).with_sign_mode(mode);
    (agent.clone(), Agent::new(agent))
}

#[test]
fn sign_checks_determinism_with_a_second_signature() {
    let (agent, mut store) = signing_store(SignMode::Deterministic);
    let identity = ed25519_identity(1, "laptop");

    let signature = store.sign(&identity, b"data").unwrap();

    assert_eq!(*signature, deterministic_signature(b"data"));
    let calls = agent.sign_calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], calls[1]);
    assert_eq!(calls[0].credential, identity.credential);
    assert_eq!(calls[0].data, b"data");
}

#[test]
fn sign_rejects_nondeterministic_signatures() {
    let (agent, mut store) = signing_store(SignMode::Varying);

    assert_eq!(
        store
            .sign(&ed25519_identity(1, "laptop"), b"data")
            .unwrap_err()
            .to_string(),
        "agent signatures are not deterministic!"
    );
    assert_eq!(agent.sign_calls().len(), 2);
}

#[test]
fn sign_propagates_agent_errors() {
    let (agent, mut store) = signing_store(SignMode::Failing("agent refused".into()));

    assert_eq!(
        store
            .sign(&ed25519_identity(1, "laptop"), b"data")
            .unwrap_err()
            .to_string(),
        "agent refused"
    );
    // it bails before asking the agent again
    assert_eq!(agent.sign_calls().len(), 1);
}
