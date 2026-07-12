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
    #[serde(default)]
    pub notify: FederationNotifyConfig,
}

/// Coalition replication webhook delivery policy.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct FederationNotifyConfig {
    #[serde(default = "default_notify_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_notify_backoff_ms")]
    pub initial_backoff_ms: u64,
    #[serde(default = "default_notify_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub fail_closed: bool,
}

fn default_notify_attempts() -> u32 {
    3
}

fn default_notify_backoff_ms() -> u64 {
    100
}

fn default_notify_timeout_secs() -> u64 {
    5
}

impl Default for FederationNotifyConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_notify_attempts(),
            initial_backoff_ms: default_notify_backoff_ms(),
            timeout_secs: default_notify_timeout_secs(),
            fail_closed: false,
        }
    }
}

/// Production PKI paths parsed from a `pki_env` file (no process environment mutation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationPkiConfig {
    pub nmb_trust: Vec<String>,
    pub nmb_signing_key: String,
    pub kas_signing_key: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
pub struct FederationPeers {
    #[serde(default)]
    pub usa_publisher: Option<String>,
    #[serde(default)]
    pub gbr_publisher: Option<String>,
    /// Webhook URL on the allied consumer notified after publisher journal append.
    #[serde(default)]
    pub gbr_notify: Option<String>,
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
        if let Some(pki_env) = &mut self.local_node.pki_env {
            if !Path::new(pki_env).is_absolute() {
                if let Some(dir) = base_dir {
                    *pki_env = dir.join(&*pki_env).to_string_lossy().into_owned();
                }
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

    pub fn client_ca_path(&self) -> Option<&str> {
        self.local_node
            .mtls
            .as_ref()
            .and_then(|m| m.client_ca.as_deref())
    }

    pub fn peer_sync_url(&self, role: &str) -> Option<&str> {
        match role {
            "usa_publisher" | "usa" => self.replication.peers.usa_publisher.as_deref(),
            "gbr_publisher" | "gbr" => self.replication.peers.gbr_publisher.as_deref(),
            _ => None,
        }
    }

    pub fn peer_notify_url(&self, role: &str) -> Option<&str> {
        match role {
            "gbr_notify" | "gbr" => self.replication.peers.gbr_notify.as_deref(),
            _ => None,
        }
    }

    /// Resolved LDAP PIP config path for this federation node.
    pub fn ldap_config_path(&self) -> &str {
        &self.local_node.ldap_config
    }

    /// Parse production PKI PEM paths from `pki_env` without mutating `std::env`.
    pub fn resolved_pki_config(&self) -> TransportResult<Option<FederationPkiConfig>> {
        let Some(path) = &self.local_node.pki_env else {
            return Ok(None);
        };
        parse_pki_env_file(path).map(Some)
    }

    pub fn notify_options(&self) -> crate::replication_notify::ReplicationNotifyOptions {
        let notify = &self.replication.notify;
        crate::replication_notify::ReplicationNotifyOptions {
            max_attempts: notify.max_attempts,
            initial_backoff_ms: notify.initial_backoff_ms,
            timeout_secs: notify.timeout_secs,
        }
    }

    pub fn notify_fail_closed(&self) -> bool {
        self.replication.notify.fail_closed
    }

    /// Wire `MIM_LDAP_PIP_CONFIG` for [`SubjectResolver::from_env`].
    ///
    /// Prefer [`ldap_config_path`] with [`SubjectResolver::from_config_path`] when possible.
    pub fn apply_ldap_env(&self) {
        std::env::set_var("MIM_LDAP_PIP_CONFIG", &self.local_node.ldap_config);
    }

    /// Load `KEY=VALUE` pairs from the configured `pki_env` file into the process environment.
    ///
    /// Prefer [`resolved_pki_config`] and explicit PEM loading to avoid global env mutation.
    pub fn apply_pki_env(&self) -> TransportResult<()> {
        let Some(config) = self.resolved_pki_config()? else {
            return Ok(());
        };
        apply_pki_config_to_env(&config);
        Ok(())
    }
}

fn parse_pki_env_file(path: impl AsRef<Path>) -> TransportResult<FederationPkiConfig> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|e| {
        TransportError::Validation(format!("read PKI env {}: {e}", path.display()))
    })?;
    let mut nmb_trust = None;
    let mut nmb_signing_key = None;
    let mut kas_signing_key = None;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            mim_crypto::ENV_NMB_TRUST => {
                nmb_trust = Some(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|segment| !segment.is_empty())
                        .map(str::to_owned)
                        .collect::<Vec<_>>(),
                );
            }
            mim_crypto::ENV_NMB_SIGNING_KEY => nmb_signing_key = Some(value.to_owned()),
            mim_crypto::ENV_KAS_SIGNING_KEY => kas_signing_key = Some(value.to_owned()),
            _ => {}
        }
    }
    let nmb_trust = nmb_trust.filter(|paths| !paths.is_empty()).ok_or_else(|| {
        TransportError::Validation(format!(
            "PKI env {} missing {}",
            path.display(),
            mim_crypto::ENV_NMB_TRUST
        ))
    })?;
    let nmb_signing_key = nmb_signing_key.ok_or_else(|| {
        TransportError::Validation(format!(
            "PKI env {} missing {}",
            path.display(),
            mim_crypto::ENV_NMB_SIGNING_KEY
        ))
    })?;
    let kas_signing_key = kas_signing_key.ok_or_else(|| {
        TransportError::Validation(format!(
            "PKI env {} missing {}",
            path.display(),
            mim_crypto::ENV_KAS_SIGNING_KEY
        ))
    })?;
    Ok(FederationPkiConfig {
        nmb_trust,
        nmb_signing_key,
        kas_signing_key,
    })
}

fn apply_pki_config_to_env(config: &FederationPkiConfig) {
    std::env::set_var(
        mim_crypto::ENV_NMB_TRUST,
        config.nmb_trust.join(","),
    );
    std::env::set_var(
        mim_crypto::ENV_NMB_SIGNING_KEY,
        &config.nmb_signing_key,
    );
    std::env::set_var(
        mim_crypto::ENV_KAS_SIGNING_KEY,
        &config.kas_signing_key,
    );
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
            assert_eq!(config.replication.notify.max_attempts, 3);
            let pki = config.resolved_pki_config().expect("pki");
            assert!(pki.is_some());
        }
    }

    #[test]
    fn resolved_pki_config_parses_without_env_mutation() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/pki.env.example");
        let config = parse_pki_env_file(&path).expect("parse");
        assert!(!config.nmb_trust.is_empty());
        assert!(!config.nmb_signing_key.is_empty());
        assert!(!config.kas_signing_key.is_empty());
    }
}
