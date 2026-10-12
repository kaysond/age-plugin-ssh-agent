mod common;

use age_core::format::{FileKey, Stanza};
use age_core::secrecy::ExposeSecret;
use age_plugin_ssh_agent::agent::Agent;
use age_plugin_ssh_agent::identity::Identity;
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use common::{KAT_RECIPIENT, MockAgent, SignMode, ed25519_identity, kat_identity, secret_of};

#[test]
fn new_uses_a_random_secret() {
    let agent_identity = ed25519_identity(1, "laptop");
    let mut store = Agent::new(MockAgent::new(vec![agent_identity.clone()]));

    let first = Identity::new(&agent_identity).unwrap();
    let second = Identity::new(&agent_identity).unwrap();

    assert_ne!(secret_of(&first), secret_of(&second));
    assert_ne!(
        first.age_recipient(&mut store).unwrap(),
        second.age_recipient(&mut store).unwrap()
    );
}

#[test]
fn recipient_matches_known_answer() {
    // the second key makes signing with the wrong one change the result
    let mut store = Agent::new(MockAgent::new(vec![
        ed25519_identity(2, "desktop"),
        ed25519_identity(1, "laptop"),
    ]));

    let recipient = kat_identity().age_recipient(&mut store).unwrap();

    assert_eq!(recipient.to_string(), KAT_RECIPIENT);
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

fn laptop_store(mode: SignMode) -> Agent<MockAgent> {
    Agent::new(MockAgent::new(vec![ed25519_identity(1, "laptop")]).with_sign_mode(mode))
}

fn valid_stanza() -> Stanza {
    kat_identity()
        .wrap_file_key(
            &mut laptop_store(SignMode::Deterministic),
            &FileKey::new(Box::new([7; 16])),
        )
        .unwrap()
}

#[test]
fn unwrap_stanza_round_trips() {
    let file_key = kat_identity()
        .unwrap_stanza(&mut laptop_store(SignMode::Deterministic), &valid_stanza())
        .unwrap()
        .unwrap();

    assert_eq!(file_key.expose_secret(), &[7; 16]);
}

#[test]
fn unwrap_stanza_ignores_other_tags() {
    let stanza = Stanza {
        tag: "X25519".into(),
        ..valid_stanza()
    };

    assert!(
        kat_identity()
            .unwrap_stanza(&mut laptop_store(SignMode::Deterministic), &stanza)
            .is_none()
    );
}

#[test]
fn unwrap_stanza_rejects_malformed_stanzas() {
    let valid = valid_stanza();
    let salt = valid.args[0].clone();
    let cases = [
        (
            vec![],
            valid.body.clone(),
            "invalid ssh-agent stanza arguments",
        ),
        (
            vec![salt.clone(), salt.clone()],
            valid.body.clone(),
            "invalid ssh-agent stanza arguments",
        ),
        (
            vec!["not base64!".into()],
            valid.body.clone(),
            "invalid ssh-agent stanza arguments",
        ),
        (
            vec![BASE64_STANDARD_NO_PAD.encode([0; 31])],
            valid.body.clone(),
            "invalid ssh-agent stanza arguments",
        ),
        (
            vec![salt.clone()],
            valid.body[..31].to_vec(),
            "invalid ssh-agent stanza body",
        ),
        (
            vec![salt],
            [&valid.body[..], &[0]].concat(),
            "invalid ssh-agent stanza body",
        ),
    ];

    for (args, body, message) in cases {
        let stanza = Stanza {
            tag: "ssh-agent".into(),
            args: args.clone(),
            body,
        };
        let result = kat_identity()
            .unwrap_stanza(&mut laptop_store(SignMode::Deterministic), &stanza)
            .expect("malformed stanza should error, not be skipped");
        assert_eq!(result.err().unwrap().to_string(), message, "args {args:?}");
    }
}

#[test]
fn unwrap_stanza_propagates_agent_errors() {
    let result = kat_identity()
        .unwrap_stanza(
            &mut laptop_store(SignMode::Failing("agent refused".into())),
            &valid_stanza(),
        )
        .expect("agent failure should error, not be skipped");

    assert_eq!(result.err().unwrap().to_string(), "agent refused");
}
