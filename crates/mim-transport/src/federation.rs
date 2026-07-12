//! FMN coalition federation configuration.

use std::path::Path;

use serde::Deserialize;

use crate::error::{TransportError, TransportResult};

/// Root federation config (`config/fmn-federation.toml`).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct FederationConfig {
    pub local_node: FederationLocalNode,
    #[serde(default)]
    pub replication: FederationReplication,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct FederationLocalNode {
    pub id: String,
    pub domain_id: String,
    pub ldap_config: String,
    #[serde(default)]
    pub pki_env: Option<String>,
    #[serde(default)]
    pub mtls: Option<FederationMtlsConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct FederationMtlsConfig {
    #[serde(default)]
    pub require_client_auth: bool,
    #[serde(default)]
    pub client_ca: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
pub struct FederationReplication {
    #[serde(default)]
    pub peers: FederationPeers,
    #[serde(default)]
    pub policy: FederationReplicationPolicy,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
pub struct FederationPeers {
    #[serde(default)]
    pub usa_publisher: Option<String>,
    #[serde(default)]
    pub gbr_publisher: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct FederationReplicationPolicy {
    #[serde(default = "default_true")]
    pub pep_filtered_sync: bool,
    #[serde(default = "default_journal_path")]
    pub journal_persistence: String,
}

fn default_true() -> bool {
    true
}

fn default_journal_path() -> String {
    "exchange.json".into()
}

impl Default for FederationReplicationPolicy {
    fn default() -> Self {
        Self {
            pep_filtered_sync: true,
            journal_persistence: default_journal_path(),
        }
    }
}

impl FederationConfig {
    pub fn load_path(path: impl AsRef<Path>) -> TransportResult<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| {
            TransportError::Validation(format!("read federation config {}: {e}", path.display()))
        })?;
        let mut config: FederationConfig = toml::from_str(&content).map_err(|e| {
            TransportError::Validation(format!("parse federation config {}: {e}", path.display()))
        })?;
        config.resolve_paths(path.parent());
        Ok(config)
    }

    pub fn from_env() -> TransportResult<Self> {
        let path = std::env::var("MIM_FEDERATION_CONFIG")
            .unwrap_or_else(|_| "config/fmn-federation.toml".into());
        Self::load_path(path)
    }

    fn resolve_paths(&mut self, base_dir: Option<&Path>) {
        if !Path::new(&self.local_node.ldap_config).is_absolute() {
            if let Some(dir) = base_dir {
                self.local_node.ldap_config = dir
                    .join(&self.local_node.ldap_config)
                    .to_string_lossy()
                    .into_owned();
            }
        }
        if let Some(mtls) = &mut self.local_node.mtls {
            if let Some(ca) = &mtls.client_ca {
                if !Path::new(ca).is_absolute() {
                    if let Some(dir) = base_dir {
                        mtls.client_ca = Some(dir.join(ca).to_string_lossy().into_owned());
                    }
                }
            }
        }
        if !Path::new(&self.replication.policy.journal_persistence).is_absolute() {
            if let Some(dir) = base_dir {
                self.replication.policy.journal_persistence = dir
                    .join(&self.replication.policy.journal_persistence)
                    .to_string_lossy()
                    .into_owned();
            }
        }
    }

    pub fn journal_path(&self) -> &str {
        &self.replication.policy.journal_persistence
    }

    pub fn require_mtls(&self) -> bool {
        self.local_node
            .mtls
            .as_ref()
            .map(|m| m.require_client_auth)
            .unwrap_or(false)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn loads_workspace_federation_config() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/fmn-federation.toml");
        if path.exists() {
            let config = FederationConfig::load_path(&path).expect("load");
            assert_eq!(config.local_node.id, "usa-national-c2");
            assert!(config.replication.policy.pep_filtered_sync);
        }
    }
}
