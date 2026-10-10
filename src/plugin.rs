//! `age-plugin` state machine handlers.
//!
//! The plugin has no recipient type of its own. Encryption works either by passing the
//! derived `age1…` recipient to age (no plugin involved) or by encrypting to the plugin
//! identity, which produces `ssh-agent` stanzas. Decryption handles both stanza kinds.

use crate::agent::{Agent, AgentClient};
use crate::identity::{Identity, STANZA_TAG};
use age::Identity as _;
use age_core::format::{FileKey, Stanza};
use age_plugin::{
    Callbacks, PluginHandler,
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
};

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io;

// age keeps its own constant private
const X25519_TAG: &str = "X25519";

/// Entry point passed to [`age_plugin::run_state_machine`].
pub struct Handler<A: AgentClient> {
    /// Agent used for every signature the plugin requests.
    pub agent: Agent<A>,
}

impl<A: AgentClient> PluginHandler for Handler<A> {
    type RecipientV1 = RecipientPlugin<A>;
    type IdentityV1 = IdentityPlugin<A>;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin {
            agent: self.agent,
            identities: vec![],
        })
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin {
            agent: self.agent,
            identities: vec![],
        })
    }
}

fn parse_identity(plugin_name: &str, bytes: &[u8]) -> Result<Identity, String> {
    if plugin_name != "ssh-agent" {
        return Err(format!("unsupported identity type: {plugin_name}"));
    }
    Identity::from_bytes(bytes).map_err(|e| format!("could not deserialize identity: {e}"))
}

/// `recipient-v1` handler: wraps file keys for plugin identities (`age -e -i`).
///
/// Rejects plugin recipients, since none exist.
pub struct RecipientPlugin<A: AgentClient> {
    agent: Agent<A>,
    identities: Vec<(usize, Identity)>,
}

impl<A: AgentClient> RecipientPluginV1 for RecipientPlugin<A> {
    fn add_recipient(
        &mut self,
        index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        Err(recipient::Error::Recipient {
            index,
            message: "age-plugin-ssh-agent does not have its own recipient type. Did you mean to encrypt with an identity?"
                .into(),
        })
    }

    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        let identity = parse_identity(plugin_name, bytes)
            .map_err(|message| recipient::Error::Identity { index, message })?;
        self.identities.push((index, identity));
        Ok(())
    }

    fn labels(&mut self) -> HashSet<String> {
        HashSet::new()
    }

    /// Produces one `ssh-agent` stanza per identity per file key, each with its own file salt.
    ///
    /// Any failure fails the whole call, returning every per-identity error.
    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        let mut files = vec![];
        let mut errors = vec![];
        for file_key in &file_keys {
            let mut stanzas = vec![];
            for (index, identity) in &self.identities {
                let _ = callbacks.message("Requesting signature from ssh agent...")?;
                match identity.wrap_file_key(&mut self.agent, file_key) {
                    Ok(stanza) => stanzas.push(stanza),
                    Err(e) => errors.push(recipient::Error::Identity {
                        index: *index,
                        message: format!("could not wrap file key: {e}"),
                    }),
                }
            }
            files.push(stanzas);
        }
        Ok(if errors.is_empty() {
            Ok(files)
        } else {
            Err(errors)
        })
    }
}

/// `identity-v1` handler: unwraps native X25519 stanzas and `ssh-agent` stanzas.
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
        let identity = parse_identity(plugin_name, bytes)
            .map_err(|message| identity::Error::Identity { index, message })?;
        self.identities.push((index, identity));
        Ok(())
    }

    /// Derives each identity's X25519 secret up front, then tries every stanza against every
    /// identity until one yields the file key. A stanza that errors for one identity is not
    /// retried with the others.
    ///
    /// An identity whose secret cannot be derived (e.g. key missing from the agent) is reported
    /// via `callbacks.error` and skipped. Files with no matching stanza are left out of the
    /// result; files where only malformed or failing stanzas matched map to their errors.
    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut secrets = vec![];
        for (index, identity) in &self.identities {
            let _ = callbacks.message("Requesting signature from ssh agent...")?;
            match identity.age_identity(&mut self.agent) {
                Ok(secret) => secrets.push((identity, secret)),
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
                for (identity, secret) in &secrets {
                    let result = match stanza.tag.as_str() {
                        X25519_TAG => secret
                            .unwrap_stanza(stanza)
                            .map(|r| r.map_err(Box::<dyn Error>::from)),
                        STANZA_TAG => identity.unwrap_stanza(&mut self.agent, stanza),
                        _ => continue 'stanzas,
                    };
                    match result {
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
