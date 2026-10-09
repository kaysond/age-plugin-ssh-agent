mod common;

use age::Recipient as _;
use age_core::format::{FileKey, Stanza};
use age_core::secrecy::{ExposeSecret, SecretString};
use age_plugin::identity::{Error, IdentityPluginV1};
use age_plugin::{Callbacks, PluginHandler};
use age_plugin_ssh_agent::agent::Agent;
use age_plugin_ssh_agent::identity::Identity;
use age_plugin_ssh_agent::plugin::Handler;
use common::{MockAgent, ed25519_identity};

struct MockCallbacks<E> {
    messages: usize,
    errors: Vec<E>,
}

impl<E> Default for MockCallbacks<E> {
    fn default() -> Self {
        MockCallbacks {
            messages: 0,
            errors: vec![],
        }
    }
}

impl<E> Callbacks<E> for &mut MockCallbacks<E> {
    fn message(&mut self, _: &str) -> age_core::plugin::Result<()> {
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
        self.errors.push(error);
        Ok(Ok(()))
    }
}

/// the bytes age hands the plugin: the identity's bech32 payload
fn identity_bytes(identity: &Identity) -> Vec<u8> {
    age_core::primitives::bech32_decode(
        &identity.to_string(),
        |e| format!("invalid bech32: {e}"),
        |_| Ok(()),
        |_, bytes| Ok(bytes.collect()),
    )
    .unwrap()
}

fn wrap(recipient: &age::x25519::Recipient, file_key: &FileKey) -> Stanza {
    recipient.wrap_file_key(file_key).unwrap().0.remove(0)
}

#[test]
fn unwraps_file_keys_with_agent_derived_secrets() {
    let agent_identity = ed25519_identity(1, "laptop");
    let mock = MockAgent::new(vec![agent_identity.clone()]);
    let identity = Identity::new(&agent_identity).unwrap();
    let missing = Identity::new(&ed25519_identity(2, "gone")).unwrap();
    let recipient = identity
        .age_recipient(&mut Agent::new(mock.clone()))
        .unwrap();
    let other = age::x25519::Identity::generate().to_public();

    let file_key = FileKey::new(Box::new([7; 16]));
    let mut malformed = wrap(&recipient, &file_key);
    malformed.body.pop();

    let mut plugin = Handler {
        agent: Agent::new(mock),
    }
    .identity_v1()
    .unwrap();
    assert!(
        plugin
            .add_identity(3, "ssh-agent", &identity_bytes(&identity))
            .is_ok()
    );
    assert!(
        plugin
            .add_identity(5, "ssh-agent", &identity_bytes(&missing))
            .is_ok()
    );

    let mut callbacks = MockCallbacks::<Error>::default();
    let mut results = plugin
        .unwrap_file_keys(
            vec![
                vec![wrap(&other, &file_key), wrap(&recipient, &file_key)],
                vec![wrap(&other, &file_key)],
                vec![malformed],
            ],
            &mut callbacks,
        )
        .unwrap();

    assert_eq!(callbacks.messages, 2);
    assert!(matches!(
        callbacks.errors[..],
        [Error::Identity { index: 5, .. }]
    ));

    let Ok(unwrapped) = results.remove(&0).unwrap() else {
        panic!("file 0 should unwrap");
    };
    assert_eq!(unwrapped.expose_secret(), file_key.expose_secret());
    assert!(!results.contains_key(&1));
    let Err(errors) = results.remove(&2).unwrap() else {
        panic!("file 2 should error");
    };
    assert!(matches!(
        errors[..],
        [Error::Stanza {
            file_index: 2,
            stanza_index: 0,
            ..
        }]
    ));
}

#[test]
fn recipient_plugin_rejects_recipients() {
    use age_plugin::recipient::{self, RecipientPluginV1};

    let mut plugin = Handler {
        agent: Agent::new(MockAgent::new(vec![])),
    }
    .recipient_v1()
    .unwrap();
    assert!(matches!(
        plugin.add_recipient(4, "ssh-agent", &[1, 2, 3]),
        Err(recipient::Error::Recipient { index: 4, .. })
    ));
}

#[test]
fn recipient_plugin_adds_identities() {
    use age_plugin::recipient::{self, RecipientPluginV1};

    let identity = Identity::new(&ed25519_identity(1, "laptop")).unwrap();
    let mut plugin = Handler {
        agent: Agent::new(MockAgent::new(vec![])),
    }
    .recipient_v1()
    .unwrap();
    assert!(
        plugin
            .add_identity(0, "ssh-agent", &identity_bytes(&identity))
            .is_ok()
    );
    assert!(matches!(
        plugin.add_identity(1, "yubikey", &identity_bytes(&identity)),
        Err(recipient::Error::Identity { index: 1, .. })
    ));
    assert!(matches!(
        plugin.add_identity(2, "ssh-agent", &[1, 2, 3]),
        Err(recipient::Error::Identity { index: 2, .. })
    ));
}

#[test]
fn wrapped_file_keys_round_trip() {
    use age_plugin::recipient::RecipientPluginV1;

    let agent_identity = ed25519_identity(1, "laptop");
    let mock = MockAgent::new(vec![agent_identity.clone()]);
    let identity = Identity::new(&agent_identity).unwrap();
    let file_keys = [[7; 16], [9; 16]];

    let mut recipient_plugin = Handler {
        agent: Agent::new(mock.clone()),
    }
    .recipient_v1()
    .unwrap();
    assert!(
        recipient_plugin
            .add_identity(0, "ssh-agent", &identity_bytes(&identity))
            .is_ok()
    );
    let mut callbacks = MockCallbacks::default();
    let Ok(files) = recipient_plugin
        .wrap_file_keys(
            file_keys
                .iter()
                .map(|k| FileKey::new(Box::new(*k)))
                .collect(),
            &mut callbacks,
        )
        .unwrap()
    else {
        panic!("wrapping should succeed");
    };

    assert_eq!(callbacks.messages, 2);
    assert!(files.iter().all(|stanzas| matches!(
        &stanzas[..],
        [Stanza { tag, args, .. }] if tag == "ssh-agent" && args.len() == 1
    )));
    assert_ne!(files[0][0].args, files[1][0].args);

    let first = &files[0][0];
    let mut tampered = Stanza {
        tag: first.tag.clone(),
        args: first.args.clone(),
        body: first.body.clone(),
    };
    tampered.body[0] ^= 1;

    let mut identity_plugin = Handler {
        agent: Agent::new(mock),
    }
    .identity_v1()
    .unwrap();
    assert!(
        identity_plugin
            .add_identity(0, "ssh-agent", &identity_bytes(&identity))
            .is_ok()
    );
    let mut callbacks = MockCallbacks::<Error>::default();
    let mut files = files;
    files.push(vec![tampered]);
    let mut results = identity_plugin
        .unwrap_file_keys(files, &mut callbacks)
        .unwrap();

    assert!(callbacks.errors.is_empty());
    for (index, file_key) in file_keys.iter().enumerate() {
        let Ok(unwrapped) = results.remove(&index).unwrap() else {
            panic!("file {index} should unwrap");
        };
        assert_eq!(unwrapped.expose_secret(), file_key);
    }
    // a stanza that fails to decrypt belongs to someone else, not an error
    assert!(results.is_empty());
}

#[test]
fn wrap_fails_for_identity_missing_from_agent() {
    use age_plugin::recipient::{self, RecipientPluginV1};

    let identity = Identity::new(&ed25519_identity(2, "gone")).unwrap();
    let mut plugin = Handler {
        agent: Agent::new(MockAgent::new(vec![ed25519_identity(1, "laptop")])),
    }
    .recipient_v1()
    .unwrap();
    assert!(
        plugin
            .add_identity(3, "ssh-agent", &identity_bytes(&identity))
            .is_ok()
    );

    let result = plugin
        .wrap_file_keys(
            vec![FileKey::new(Box::new([7; 16]))],
            &mut MockCallbacks::default(),
        )
        .unwrap();
    assert!(matches!(
        result.as_ref().map_err(Vec::as_slice),
        Err([recipient::Error::Identity { index: 3, .. }])
    ));
}
