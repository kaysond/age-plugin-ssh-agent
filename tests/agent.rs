mod common;

use age_plugin_ssh_agent::agent::IdentityStore;
use common::{MockAgent, ed25519_credential, ed25519_identity, sk_ed25519_identity};

// computed outside of ssh-key, so this pins the fingerprint format rather than re-deriving it:
// unpadded base64 of sha256(string("ssh-ed25519") ‖ string([1u8; 32]))
const FINGERPRINT_1: &str = "SHA256:RXm/ruZ0eTzRXKwi1AQEDynB0VgHQ2ac9KPSFdf/YnA";

fn store_with_two_keys() -> IdentityStore<MockAgent> {
    IdentityStore::new(MockAgent::new(vec![
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
    let mut store = IdentityStore::new(agent);

    assert_eq!(
        store.identities().unwrap().to_vec(),
        vec![ed25519_identity(1, "laptop")]
    );
}

#[test]
fn identities_errors_when_no_ed25519() {
    let agent = MockAgent::new(vec![sk_ed25519_identity(2, "fido")]);
    let mut store = IdentityStore::new(agent.clone());

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
    let mut store = IdentityStore::new(agent.clone());

    let first = store.identities().unwrap().to_vec();
    let second = store.identities().unwrap().to_vec();

    assert_eq!(first, second);
    assert_eq!(agent.request_identities_calls(), 1);
}

#[test]
fn identities_propagates_agent_error() {
    let mut store = IdentityStore::new(MockAgent::failing_identities("agent is not running"));

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
