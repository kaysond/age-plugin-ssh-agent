mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::thread;

use age_plugin_ssh_agent::agent::{Agent, AgentClient, SIGNATURE_LEN};
use common::{
    MockAgent, SignMode, deterministic_signature, ed25519_credential, ed25519_identity,
    sk_ed25519_identity,
};
use ssh_agent_lib::blocking::Client;
use ssh_agent_lib::proto::{Request, Response};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use ssh_agent_lib::ssh_key::HashAlg::{Sha256, Sha512};
use ssh_agent_lib::ssh_key::{Algorithm, Signature};

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

    assert_eq!(store.find_string(FINGERPRINT_1).unwrap().comment, "laptop");
}

#[test]
fn find_requires_sha256_prefix() {
    let mut store = store_with_two_keys();
    let bare = FINGERPRINT_1.strip_prefix("SHA256:").unwrap();

    for string in [bare, "desktop"] {
        assert_eq!(
            store.find_string(string).unwrap_err().to_string(),
            "identity string must start with 'SHA256:'"
        );
    }
}

#[test]
fn find_errors_for_unknown() {
    let mut store = store_with_two_keys();
    let unknown = ed25519_credential(9).key_data().fingerprint(Sha256);

    assert_eq!(
        store
            .find_string(&unknown.to_string())
            .unwrap_err()
            .to_string(),
        "could not find matching identity"
    );
}

#[test]
fn find_ignores_filtered_identities() {
    let mut store = store_with_two_keys();
    let fido = sk_ed25519_identity(2, "fido")
        .credential
        .key_data()
        .fingerprint(Sha256);

    assert_eq!(
        store
            .find_string(&fido.to_string())
            .unwrap_err()
            .to_string(),
        "could not find matching identity"
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

    assert_eq!(
        *signature,
        deterministic_signature(&identity.credential, b"data")
    );
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

#[test]
fn sign_propagates_errors_from_the_second_signature() {
    let (agent, mut store) = signing_store(SignMode::FailAfter(1, "agent refused".into()));

    assert_eq!(
        store
            .sign(&ed25519_identity(1, "laptop"), b"data")
            .unwrap_err()
            .to_string(),
        "agent refused"
    );
    assert_eq!(agent.sign_calls().len(), 2);
}

/// A real `Client` connected to a fake agent that answers every request with `response`.
fn client_with_response(response: Response) -> Client<UnixStream> {
    let (client, mut server) = UnixStream::pair().unwrap();
    thread::spawn(move || {
        let mut len = [0; 4];
        while server.read_exact(&mut len).is_ok() {
            let mut request = vec![0; u32::from_be_bytes(len) as usize];
            server.read_exact(&mut request).unwrap();
            Request::decode(&mut &request[..]).unwrap();

            let mut bytes = vec![];
            (response.encoded_len().unwrap() as u32)
                .encode(&mut bytes)
                .unwrap();
            response.encode(&mut bytes).unwrap();
            server.write_all(&bytes).unwrap();
        }
    });
    Client::new(client)
}

#[test]
fn unix_client_lists_identities() {
    let identities = vec![
        ed25519_identity(1, "laptop"),
        sk_ed25519_identity(2, "fido"),
    ];
    let mut client = client_with_response(Response::IdentitiesAnswer(identities.clone()));

    assert_eq!(
        AgentClient::request_identities(&mut client).unwrap(),
        identities
    );
}

#[test]
fn unix_client_returns_the_signature() {
    let signature = Signature::new(Algorithm::Ed25519, [5; SIGNATURE_LEN]).unwrap();
    let mut client = client_with_response(Response::SignResponse(signature));

    let signed = AgentClient::sign(&mut client, &ed25519_credential(1), b"data").unwrap();

    assert_eq!(*signed, [5; SIGNATURE_LEN]);
}

#[test]
fn unix_client_rejects_wrong_size_signatures() {
    // Ed25519 signatures can't be built with the wrong size, but RSA ones can
    let signature = Signature::new(
        Algorithm::Rsa { hash: Some(Sha512) },
        [5; SIGNATURE_LEN - 1],
    )
    .unwrap();
    let mut client = client_with_response(Response::SignResponse(signature));

    assert_eq!(
        AgentClient::sign(&mut client, &ed25519_credential(1), b"data")
            .unwrap_err()
            .to_string(),
        "agent returned a signature with the wrong size"
    );
}
