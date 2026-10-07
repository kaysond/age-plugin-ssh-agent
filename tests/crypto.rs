mod common;

use age_plugin_ssh_agent::agent::Agent;
use age_plugin_ssh_agent::crypto::{NAMESPACE, sign_identity};
use age_plugin_ssh_agent::identity::Identity;
use common::{MockAgent, deterministic_signature, ed25519_identity, salt_of};

#[test]
fn sign_identity_signs_namespace_and_salt() {
    let agent = MockAgent::default();
    let mut store = Agent::new(agent.clone());
    let agent_identity = ed25519_identity(1, "laptop");
    let identity = Identity::new(&agent_identity).unwrap();

    let signature = sign_identity(&identity, &mut store, &agent_identity, None).unwrap();

    let data = [NAMESPACE, &salt_of(&identity)].concat();
    assert_eq!(*signature, deterministic_signature(&data));
    assert_eq!(agent.sign_calls()[0].credential, agent_identity.credential);
    assert_eq!(agent.sign_calls()[0].data, data);
}

#[test]
fn sign_identity_appends_extra_salt() {
    let agent = MockAgent::default();
    let mut store = Agent::new(agent.clone());
    let agent_identity = ed25519_identity(1, "laptop");
    let identity = Identity::new(&agent_identity).unwrap();

    sign_identity(&identity, &mut store, &agent_identity, Some([7; 32])).unwrap();

    assert_eq!(
        agent.sign_calls()[0].data,
        [NAMESPACE, &salt_of(&identity), &[7; 32]].concat()
    );
}
