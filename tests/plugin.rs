mod common;

use std::collections::HashMap;
use std::io;

use age::Recipient as _;
use age_core::format::{FileKey, Stanza};
use age_core::secrecy::{ExposeSecret, SecretString};
use age_plugin::identity::{Error, IdentityPluginV1};
use age_plugin::recipient::{self, RecipientPluginV1};
use age_plugin::{Callbacks, PluginHandler};
use age_plugin_ssh_agent::agent::Agent;
use age_plugin_ssh_agent::identity::Identity;
use age_plugin_ssh_agent::plugin::{Handler, IdentityPlugin, RecipientPlugin};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use common::{KAT_RECIPIENT, MockAgent, SignMode, ed25519_identity, identity_bytes, kat_identity};

/// age-plugin's errors are not `Debug`; this surfaces their messages when a test fails.
trait Message {
    fn message(&self) -> &str;
}

impl Message for Error {
    fn message(&self) -> &str {
        match self {
            Error::Identity { message, .. }
            | Error::Internal { message }
            | Error::Stanza { message, .. } => message,
        }
    }
}

impl Message for recipient::Error {
    fn message(&self) -> &str {
        match self {
            recipient::Error::Identity { message, .. }
            | recipient::Error::Internal { message }
            | recipient::Error::Recipient { message, .. } => message,
        }
    }
}

fn ok<T, E: Message>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|e| panic!("unexpected error: {}", e.message()))
}

fn ok_all<T, E: Message>(result: Result<T, Vec<E>>) -> T {
    result.unwrap_or_else(|errors| panic!("unexpected errors: {:?}", messages(&errors)))
}

fn messages<E: Message>(errors: &[E]) -> Vec<&str> {
    errors.iter().map(Message::message).collect()
}

struct MockCallbacks<E> {
    messages: usize,
    errors: Vec<E>,
    fail_messages: bool,
    fail_errors: bool,
}

impl<E> Default for MockCallbacks<E> {
    fn default() -> Self {
        MockCallbacks {
            messages: 0,
            errors: vec![],
            fail_messages: false,
            fail_errors: false,
        }
    }
}

impl<E> Callbacks<E> for &mut MockCallbacks<E> {
    fn message(&mut self, _: &str) -> age_core::plugin::Result<()> {
        if self.fail_messages {
            return Err(io::Error::other("client went away"));
        }
        self.messages += 1;
        Ok(Ok(()))
    }
    fn confirm(&mut self, _: &str, _: &str, _: Option<&str>) -> age_core::plugin::Result<bool> {
        unimplemented!()
    }
    fn request_public(&mut self, _: &str) -> age_core::plugin::Result<String> {
        unimplemented!()
    }
    fn request_secret(&mut self, _: &str) -> age_core::plugin::Result<SecretString> {
        unimplemented!()
    }
    fn error(&mut self, error: E) -> age_core::plugin::Result<()> {
        if self.fail_errors {
            return Err(io::Error::other("client went away"));
        }
        self.errors.push(error);
        Ok(Ok(()))
    }
}

/// agent holding the KAT identity's key
fn laptop_agent() -> MockAgent {
    MockAgent::new(vec![ed25519_identity(1, "laptop")])
}

fn identity_plugin(
    mock: MockAgent,
    identities: &[(usize, &Identity)],
) -> IdentityPlugin<MockAgent> {
    let mut plugin = Handler {
        agent: Agent::new(mock),
    }
    .identity_v1()
    .unwrap();
    for (index, identity) in identities {
        ok(plugin.add_identity(*index, "ssh-agent", &identity_bytes(identity)));
    }
    plugin
}

fn recipient_plugin(
    mock: MockAgent,
    identities: &[(usize, &Identity)],
) -> RecipientPlugin<MockAgent> {
    let mut plugin = Handler {
        agent: Agent::new(mock),
    }
    .recipient_v1()
    .unwrap();
    for (index, identity) in identities {
        ok(plugin.add_identity(*index, "ssh-agent", &identity_bytes(identity)));
    }
    plugin
}

fn file_key() -> FileKey {
    FileKey::new(Box::new([7; 16]))
}

fn x25519_stanza(recipient: &age::x25519::Recipient) -> Stanza {
    recipient.wrap_file_key(&file_key()).unwrap().0.remove(0)
}

fn kat_x25519_stanza() -> Stanza {
    x25519_stanza(&KAT_RECIPIENT.parse().unwrap())
}

fn foreign_x25519_stanza() -> Stanza {
    x25519_stanza(&age::x25519::Identity::generate().to_public())
}

fn ssh_agent_stanza() -> Stanza {
    kat_identity()
        .wrap_file_key(&mut Agent::new(laptop_agent()), &file_key())
        .unwrap()
}

type Results = HashMap<usize, Result<FileKey, Vec<Error>>>;

fn unwrap_files(
    plugin: &mut IdentityPlugin<MockAgent>,
    files: Vec<Vec<Stanza>>,
) -> (MockCallbacks<Error>, Results) {
    let mut callbacks = MockCallbacks::default();
    let results = plugin.unwrap_file_keys(files, &mut callbacks).unwrap();
    (callbacks, results)
}

#[test]
fn unwraps_x25519_stanzas_with_the_agent_derived_secret() {
    let mut plugin = identity_plugin(laptop_agent(), &[(3, &kat_identity())]);

    let (callbacks, mut results) = unwrap_files(
        &mut plugin,
        vec![vec![foreign_x25519_stanza(), kat_x25519_stanza()]],
    );

    assert_eq!(callbacks.messages, 1);
    assert!(callbacks.errors.is_empty());
    let unwrapped = ok_all(results.remove(&0).unwrap());
    assert_eq!(unwrapped.expose_secret(), file_key().expose_secret());
}

#[test]
fn skips_files_with_only_foreign_stanzas() {
    let mut plugin = identity_plugin(laptop_agent(), &[(3, &kat_identity())]);
    let unknown = Stanza {
        tag: "scrypt".into(),
        args: vec!["salt".into(), "18".into()],
        body: vec![0; 32],
    };

    let (callbacks, results) = unwrap_files(
        &mut plugin,
        vec![vec![foreign_x25519_stanza()], vec![unknown]],
    );

    assert!(callbacks.errors.is_empty());
    assert!(results.is_empty());
}

#[test]
fn reports_malformed_x25519_stanzas() {
    let mut plugin = identity_plugin(laptop_agent(), &[(3, &kat_identity())]);
    let mut malformed = kat_x25519_stanza();
    malformed.body.pop();

    let (_, mut results) = unwrap_files(&mut plugin, vec![vec![malformed]]);

    let errors = results.remove(&0).unwrap().err().unwrap();
    assert!(matches!(
        errors[..],
        [Error::Stanza {
            file_index: 0,
            stanza_index: 0,
            ..
        }]
    ));
}

#[test]
fn reports_malformed_ssh_agent_stanzas() {
    let mut plugin = identity_plugin(laptop_agent(), &[(3, &kat_identity())]);
    let malformed = Stanza {
        args: vec![],
        ..ssh_agent_stanza()
    };

    let (_, mut results) =
        unwrap_files(&mut plugin, vec![vec![foreign_x25519_stanza(), malformed]]);

    let errors = results.remove(&0).unwrap().err().unwrap();
    let [
        Error::Stanza {
            file_index: 0,
            stanza_index: 1,
            message,
        },
    ] = &errors[..]
    else {
        panic!("expected one stanza error, got {:?}", messages(&errors));
    };
    assert_eq!(message, "invalid ssh-agent stanza arguments");
}

#[test]
fn reports_agent_failures_while_unwrapping() {
    // deriving the X25519 secret takes the first two signatures
    let mock = laptop_agent().with_sign_mode(SignMode::FailAfter(2, "agent refused".into()));
    let mut plugin = identity_plugin(mock, &[(3, &kat_identity())]);

    let (_, mut results) = unwrap_files(&mut plugin, vec![vec![ssh_agent_stanza()]]);

    let errors = results.remove(&0).unwrap().err().unwrap();
    let [
        Error::Stanza {
            file_index: 0,
            stanza_index: 0,
            message,
        },
    ] = &errors[..]
    else {
        panic!("expected one stanza error, got {:?}", messages(&errors));
    };
    assert_eq!(message, "agent refused");
}

#[test]
fn reports_identities_missing_from_the_agent() {
    let missing = Identity::new(&ed25519_identity(2, "gone")).unwrap();
    let mut plugin = identity_plugin(laptop_agent(), &[(3, &kat_identity()), (5, &missing)]);

    let (callbacks, mut results) = unwrap_files(&mut plugin, vec![vec![kat_x25519_stanza()]]);

    assert_eq!(callbacks.messages, 2);
    assert!(matches!(
        callbacks.errors[..],
        [Error::Identity { index: 5, .. }]
    ));
    // the identity that is present still unwraps
    ok_all(results.remove(&0).unwrap());
}

#[test]
fn unwrap_propagates_callback_failures() {
    let missing = Identity::new(&ed25519_identity(2, "gone")).unwrap();
    let mut plugin = identity_plugin(laptop_agent(), &[(5, &missing)]);

    for mut callbacks in [
        MockCallbacks::<Error> {
            fail_messages: true,
            ..Default::default()
        },
        MockCallbacks {
            fail_errors: true,
            ..Default::default()
        },
    ] {
        assert!(
            plugin
                .unwrap_file_keys(vec![vec![kat_x25519_stanza()]], &mut callbacks)
                .is_err()
        );
    }
}

#[test]
fn identity_plugin_rejects_bad_identities() {
    let mut plugin = identity_plugin(laptop_agent(), &[]);
    let identity = identity_bytes(&kat_identity());

    assert!(matches!(
        plugin.add_identity(1, "yubikey", &identity),
        Err(Error::Identity { index: 1, .. })
    ));
    assert!(matches!(
        plugin.add_identity(2, "ssh-agent", &[1, 2, 3]),
        Err(Error::Identity { index: 2, .. })
    ));
}

#[test]
fn recipient_plugin_rejects_recipients() {
    let mut plugin = recipient_plugin(MockAgent::default(), &[]);
    assert!(matches!(
        plugin.add_recipient(4, "ssh-agent", &[1, 2, 3]),
        Err(recipient::Error::Recipient { index: 4, .. })
    ));
}

#[test]
fn recipient_plugin_rejects_bad_identities() {
    let mut plugin = recipient_plugin(MockAgent::default(), &[]);
    let identity = identity_bytes(&kat_identity());

    ok(plugin.add_identity(0, "ssh-agent", &identity));
    assert!(matches!(
        plugin.add_identity(1, "yubikey", &identity),
        Err(recipient::Error::Identity { index: 1, .. })
    ));
    assert!(matches!(
        plugin.add_identity(2, "ssh-agent", &[1, 2, 3]),
        Err(recipient::Error::Identity { index: 2, .. })
    ));
}

#[test]
fn recipient_plugin_has_no_labels() {
    assert!(
        recipient_plugin(MockAgent::default(), &[])
            .labels()
            .is_empty()
    );
}

#[test]
fn wrapped_file_keys_round_trip() {
    let identity = kat_identity();
    let file_keys = [[7; 16], [9; 16]];

    let mut plugin = recipient_plugin(laptop_agent(), &[(0, &identity)]);
    let mut callbacks = MockCallbacks::default();
    let files = plugin
        .wrap_file_keys(
            file_keys
                .iter()
                .map(|k| FileKey::new(Box::new(*k)))
                .collect(),
            &mut callbacks,
        )
        .unwrap();
    let files = ok_all(files);

    assert_eq!(callbacks.messages, 2);
    for stanzas in &files {
        let [Stanza { tag, args, body }] = &stanzas[..] else {
            panic!("expected one stanza per file");
        };
        assert_eq!(tag, "ssh-agent");
        // pin the wire format: unpadded base64 of a 32-byte salt, 16-byte key + 16-byte tag
        let [salt] = &args[..] else {
            panic!("expected one stanza argument");
        };
        assert_eq!(salt.len(), 43);
        assert_eq!(BASE64_STANDARD_NO_PAD.decode(salt).unwrap().len(), 32);
        assert_eq!(body.len(), 32);
    }
    assert_ne!(files[0][0].args, files[1][0].args);

    let first = &files[0][0];
    let mut tampered = Stanza {
        tag: first.tag.clone(),
        args: first.args.clone(),
        body: first.body.clone(),
    };
    tampered.body[0] ^= 1;
    let mut files = files;
    files.push(vec![tampered]);

    let mut plugin = identity_plugin(laptop_agent(), &[(0, &identity)]);
    let (callbacks, mut results) = unwrap_files(&mut plugin, files);

    assert_eq!(callbacks.messages, 1);
    assert!(callbacks.errors.is_empty());
    for (index, file_key) in file_keys.iter().enumerate() {
        let unwrapped = ok_all(results.remove(&index).unwrap());
        assert_eq!(unwrapped.expose_secret(), file_key);
    }
    // a stanza that fails to decrypt belongs to someone else, not an error
    assert!(results.is_empty());
}

#[test]
fn wraps_for_every_identity() {
    let desktop = Identity::new(&ed25519_identity(2, "desktop")).unwrap();
    let mock = MockAgent::new(vec![
        ed25519_identity(1, "laptop"),
        ed25519_identity(2, "desktop"),
    ]);
    let mut plugin = recipient_plugin(mock, &[(0, &kat_identity()), (1, &desktop)]);

    let files = plugin
        .wrap_file_keys(vec![file_key(), file_key()], &mut MockCallbacks::default())
        .unwrap();
    let files = ok_all(files);

    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|stanzas| stanzas.len() == 2));
}

#[test]
fn wrap_fails_for_identity_missing_from_agent() {
    let missing = Identity::new(&ed25519_identity(2, "gone")).unwrap();
    let mut plugin = recipient_plugin(laptop_agent(), &[(0, &kat_identity()), (3, &missing)]);

    let result = plugin
        .wrap_file_keys(vec![file_key()], &mut MockCallbacks::default())
        .unwrap();

    assert!(matches!(
        result.as_ref().map_err(Vec::as_slice),
        Err([recipient::Error::Identity { index: 3, .. }])
    ));
}

#[test]
fn wrap_propagates_callback_failures() {
    let mut plugin = recipient_plugin(laptop_agent(), &[(0, &kat_identity())]);
    let mut callbacks = MockCallbacks {
        fail_messages: true,
        ..Default::default()
    };

    assert!(
        plugin
            .wrap_file_keys(vec![file_key()], &mut callbacks)
            .is_err()
    );
}
