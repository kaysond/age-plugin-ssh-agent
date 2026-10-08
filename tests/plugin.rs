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

#[derive(Default)]
struct MockCallbacks {
    messages: usize,
    errors: Vec<Error>,
}

impl Callbacks<Error> for &mut MockCallbacks {
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
    fn error(&mut self, error: Error) -> age_core::plugin::Result<()> {
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

    let mut callbacks = MockCallbacks::default();
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
