use crate::agent::{Agent, AgentClient};
use crate::identity::Identity;
use age::Identity as _;
use age_core::format::{FileKey, Stanza};
use age_plugin::{
    Callbacks, PluginHandler,
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
};

use std::collections::{HashMap, HashSet};
use std::io;
pub struct Handler<A: AgentClient> {
    pub agent: Agent<A>,
}

impl<A: AgentClient> PluginHandler for Handler<A> {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = IdentityPlugin<A>;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin)
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin {
            agent: self.agent,
            identities: vec![],
        })
    }
}

pub struct RecipientPlugin;

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn labels(&mut self) -> HashSet<String> {
        todo!()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        todo!()
    }
}

pub struct IdentityPlugin<A: AgentClient> {
    agent: Agent<A>,
    identities: Vec<(usize, Identity)>,
}

impl<A: AgentClient> IdentityPluginV1 for IdentityPlugin<A> {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name != "ssh-agent" {
            return Err(identity::Error::Identity {
                index,
                message: format!("unsupported identity type: {plugin_name}"),
            });
        }
        let identity = Identity::from_bytes(bytes).map_err(|e| identity::Error::Identity {
            index,
            message: format!("could not deserialize identity: {}", e.to_string()),
        })?;
        self.identities.push((index, identity));
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut secrets = vec![];
        for (index, identity) in &self.identities {
            let _ = callbacks.message("Requesting signature from ssh agent...")?;
            match identity.age_identity(&mut self.agent) {
                Ok(secret) => secrets.push(secret),
                Err(e) => {
                    let _ = callbacks.error(identity::Error::Identity {
                        index: *index,
                        message: format!("could not derive secret: {e}"),
                    })?;
                }
            }
        }

        let mut results = HashMap::new();
        'files: for (file_index, stanzas) in files.iter().enumerate() {
            let mut errors = vec![];
            'stanzas: for (stanza_index, stanza) in stanzas.iter().enumerate() {
                for secret in &secrets {
                    match secret.unwrap_stanza(stanza) {
                        Some(Ok(file_key)) => {
                            results.insert(file_index, Ok(file_key));
                            continue 'files;
                        }
                        Some(Err(e)) => {
                            errors.push(identity::Error::Stanza {
                                file_index,
                                stanza_index,
                                message: e.to_string(),
                            });
                            continue 'stanzas;
                        }
                        None => {}
                    }
                }
            }
            if !errors.is_empty() {
                results.insert(file_index, Err(errors));
            }
        }
        Ok(results)
    }
}
