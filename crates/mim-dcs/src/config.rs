//! Configurable DCS guard — domains, cross-domain policies, and SPIF sources from file.

use std::fs;
use std::path::{Path, PathBuf};

use mim_labeling::{DomainId, SecurityDomain};
use mim_policy::{
    apply_spif_to_store, CrossDomainPolicy, DowngradeConfig,
    PolicyDecisionPoint, PolicyEnforcementPoint, PolicyInformationPoint, PolicyStore,
};
use mim_spif::SpifRegistry;
use serde::{Deserialize, Serialize};

use crate::guard::CrossDomainGuard;

/// Audit sink type for durable guard audit trails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum AuditSinkType {
    #[default]
    File,
    Worm,
}

/// Optional durable audit configuration for DCS guard operations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditConfig {
    /// Append-only envelope JSONL path for guard/transfer audit records.
    #[serde(default)]
    pub path: Option<String>,
    /// Optional SIEM JSON export path written after each guarded transfer.
    #[serde(default)]
    pub siem_export_path: Option<String>,
    /// Sink type: `file` (append-only JSONL) or `worm` (write-once with manifest).
    #[serde(default)]
    pub sink_type: AuditSinkType,
    /// Accredited audit profile — requires WORM sink, signed records, fail-closed forwarding.
    #[serde(default)]
    pub accredited: bool,
    /// HTTP SIEM collector endpoint (`http://host:port/path`).
    #[serde(default)]
    pub siem_endpoint: Option<String>,
    /// RFC 5424 syslog TCP endpoint (`host:port` or `tcp://host:port`).
    #[serde(default)]
    pub syslog_endpoint: Option<String>,
    /// Require NMBS-signed audit envelopes (implicit when accredited).
    #[serde(default)]
    pub require_signed: bool,
    /// Fail closed when audit persistence or SIEM forwarding fails (implicit when accredited).
    #[serde(default)]
    pub fail_closed: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: None,
            siem_export_path: None,
            sink_type: AuditSinkType::default(),
            accredited: false,
            siem_endpoint: None,
            syslog_endpoint: None,
            require_signed: false,
            fail_closed: false,
        }
    }
}

/// Full DCS deployment configuration (TOML/JSON).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DcsConfig {
    #[serde(default)]
    pub domains: Vec<DomainConfig>,
    #[serde(default)]
    pub cross_domain: Vec<CrossDomainRuleConfig>,
    #[serde(default)]
    pub spif: SpifSourceConfig,
    #[serde(default)]
    pub downgrade: DowngradeConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    /// Accredited guard profile — production PKI only, mandatory WORM audit, fail-closed.
    #[serde(default)]
    pub accredited: bool,
    #[serde(skip)]
    config_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainConfig {
    pub id: String,
    pub name: String,
    pub max_classification: String,
    #[serde(default)]
    pub releasable_to: Vec<String>,
    #[serde(default)]
    pub accepted_nationalities: Vec<String>,
    #[serde(default)]
    pub mission_compartments: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossDomainRuleConfig {
    pub id: String,
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SpifSourceConfig {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_true")]
    pub validate_xsd: bool,
}

fn default_true() -> bool {
    true
}

impl Default for DcsConfig {
    fn default() -> Self {
        Self::conformance_high_to_low()
    }
}

impl DcsConfig {
    pub fn conformance_high_to_low() -> Self {
        Self {
            domains: vec![
                DomainConfig {
                    id: "DOMAIN-HIGH".into(),
                    name: "High Side".into(),
                    max_classification: "SECRET".into(),
                    releasable_to: vec!["USA".into(), "GBR".into(), "DEU".into()],
                    accepted_nationalities: vec!["USA".into(), "GBR".into(), "DEU".into()],
                    mission_compartments: Vec::new(),
                },
                DomainConfig {
                    id: "DOMAIN-LOW".into(),
                    name: "Low Side".into(),
                    max_classification: "RESTRICTED".into(),
                    releasable_to: vec!["USA".into(), "GBR".into()],
                    accepted_nationalities: vec!["USA".into(), "GBR".into()],
                    mission_compartments: Vec::new(),
                },
            ],
            cross_domain: vec![CrossDomainRuleConfig {
                id: "high-to-low".into(),
                source: "DOMAIN-HIGH".into(),
                target: "DOMAIN-LOW".into(),
                description: Some("High-side to low-side cross-domain guard".into()),
            }],
            spif: SpifSourceConfig {
                paths: vec![],
                validate_xsd: true,
            },
            downgrade: DowngradeConfig::default(),
            audit: AuditConfig::default(),
            accredited: false,
            config_dir: None,
        }
    }

    /// Whether this deployment uses the accredited guard profile (guard or audit section).
    pub fn is_accredited_profile(&self) -> bool {
        self.accredited || self.audit.accredited
    }

    /// Validate accredited profile requirements before building guard/audit.
    pub fn validate_accredited_profile(&self) -> Result<(), String> {
        if !self.is_accredited_profile() {
            return Ok(());
        }
        if self.audit.path.is_none() {
            return Err("accredited guard requires audit.path (WORM sink)".into());
        }
        if self.audit.sink_type != AuditSinkType::Worm {
            return Err("accredited guard requires audit.sinkType = worm".into());
        }
        Ok(())
    }

    fn resolve_audit_path(&self, path: &str) -> PathBuf {
        self.resolve_relative_path(path)
    }

    pub fn resolved_siem_export_path(&self) -> Option<PathBuf> {
        self.audit
            .siem_export_path
            .as_ref()
            .map(|path| self.resolve_relative_path(path))
    }

    fn resolve_relative_path(&self, path: &str) -> PathBuf {
        let direct = PathBuf::from(path);
        if direct.is_absolute() {
            return direct;
        }
        if let Some(dir) = &self.config_dir {
            let from_config = dir.join(path);
            if from_config.parent().is_some() {
                return from_config;
            }
        }
        workspace_root().join(path)
    }

    pub fn build_audit_log(&self) -> Result<Option<mim_audit::AuditLog>, String> {
        self.validate_accredited_profile()?;
        let Some(path) = &self.audit.path else {
            if self.is_accredited_profile() {
                return Err("accredited guard requires audit.path".into());
            }
            return Ok(None);
        };
        let resolved = self.resolve_audit_path(path);
        let log = match self.audit.sink_type {
            AuditSinkType::File => {
                mim_audit::AuditLog::file(&resolved).map_err(|e| e.to_string())?
            }
            AuditSinkType::Worm => {
                mim_audit::AuditLog::worm(&resolved).map_err(|e| e.to_string())?
            }
        };
        Ok(Some(log))
    }

    /// Forward audit to configured SIEM/syslog endpoints. Fails when accredited and forwarding errors.
    pub fn forward_audit_siem(&self, log: &mim_audit::AuditLog) -> Result<(), String> {
        let fail_closed = self.audit.fail_closed || self.is_accredited_profile();
        let max_attempts = if self.is_accredited_profile() { 3 } else { 1 };

        if let Some(path) = self.resolved_siem_export_path() {
            let result = mim_audit::forward_siem_to_file(log, &path);
            if fail_closed {
                result?;
            }
        }

        if let Some(endpoint) = &self.audit.siem_endpoint {
            let result =
                mim_audit::forward_log_http_accredited(log, endpoint, max_attempts);
            if fail_closed {
                result?;
            }
        }

        if let Some(endpoint) = &self.audit.syslog_endpoint {
            let result =
                mim_audit::forward_log_syslog_accredited(log, endpoint, max_attempts);
            if fail_closed {
                result?;
            }
        }

        Ok(())
    }

    pub fn from_toml_str(data: &str) -> Result<Self, String> {
        toml::from_str(data).map_err(|e| e.to_string())
    }

    pub fn from_json_str(data: &str) -> Result<Self, String> {
        serde_json::from_str(data).map_err(|e| e.to_string())
    }

    pub fn load_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let data = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut config = match path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
        {
            "json" => Self::from_json_str(&data)?,
            _ => Self::from_toml_str(&data)?,
        };
        config.config_dir = path.parent().map(Path::to_path_buf);
        Ok(config)
    }

    fn resolve_spif_path(&self, path: &str) -> PathBuf {
        let direct = PathBuf::from(path);
        if direct.is_file() {
            return direct;
        }
        if let Some(dir) = &self.config_dir {
            let from_config = dir.join(path);
            if from_config.is_file() {
                return from_config;
            }
        }
        workspace_root().join(path)
    }

    pub fn load_spif_registry(&self) -> Result<SpifRegistry, String> {
        let mut registry = SpifRegistry::new();
        for path in &self.spif.paths {
            let resolved = self.resolve_spif_path(path);
            let xml = fs::read_to_string(&resolved).map_err(|e| {
                format!("failed to read SPIF {}: {e}", resolved.display())
            })?;
            if self.spif.validate_xsd {
                mim_spif::validate_spif_xsd(&xml)?;
            }
            registry
                .load_xml(&xml)
                .map_err(|e| format!("SPIF parse error in {path}: {e}"))?;
        }
        Ok(registry)
    }

    pub fn build_policy_store(&self) -> Result<PolicyStore, String> {
        let mut store = PolicyStore::new().with_downgrade_config(self.downgrade.clone());
        for domain in &self.domains {
            store
                .insert_domain(domain.to_security_domain()?)
                .map_err(|e| e.to_string())?;
        }
        for rule in &self.cross_domain {
            let mut policy = CrossDomainPolicy::new(
                rule.id.clone(),
                DomainId::new(&rule.source),
                DomainId::new(&rule.target),
            );
            if let Some(desc) = &rule.description {
                policy = policy.with_description(desc.clone());
            }
            store
                .insert_cross_domain_policy(policy)
                .map_err(|e| e.to_string())?;
        }
        if !self.spif.paths.is_empty() {
            let registry = self.load_spif_registry()?;
            for spif in registry.policies() {
                store
                    .register_spif_policy(spif.clone())
                    .map_err(|e| e.to_string())?;
            }
            apply_spif_to_store(&mut store, &registry).map_err(|e| e.to_string())?;
        }
        Ok(store)
    }

    pub fn build_guard(&self) -> Result<CrossDomainGuard, String> {
        self.validate_accredited_profile()?;
        let store = self.build_policy_store()?;
        let (source, target) = self.primary_domain_pair()?;
        let mut pep = PolicyEnforcementPoint::new(
            PolicyInformationPoint::new(),
            PolicyDecisionPoint::new(store),
        );
        if let Some(audit) = self.build_audit_log()? {
            pep = pep.with_audit(audit);
        }
        Ok(CrossDomainGuard::from_policy_plane(pep, source, target)
            .with_accredited(self.is_accredited_profile()))
    }

    pub fn primary_domain_pair(&self) -> Result<(SecurityDomain, SecurityDomain), String> {
        let rule = self
            .cross_domain
            .first()
            .ok_or_else(|| "DCS config requires at least one cross_domain rule".to_string())?;
        let source = self.domain_by_id(&rule.source)?.to_security_domain()?;
        let target = self.domain_by_id(&rule.target)?.to_security_domain()?;
        Ok((source, target))
    }

    fn domain_by_id(&self, id: &str) -> Result<&DomainConfig, String> {
        self.domains
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| format!("unknown domain id '{id}'"))
    }
}

impl DomainConfig {
    pub fn to_security_domain(&self) -> Result<SecurityDomain, String> {
        let max = mim_labeling::ClassificationLevel::parse(&self.max_classification)
            .map_err(|e| e.to_string())?;
        let mut domain = SecurityDomain::new(&self.id, &self.name, max);
        if !self.releasable_to.is_empty() {
            domain = domain.with_releasable_to(self.releasable_to.clone());
        }
        if !self.accepted_nationalities.is_empty() {
            domain = domain.with_accepted_nationalities(self.accepted_nationalities.clone());
        }
        if !self.mission_compartments.is_empty() {
            domain = domain.with_mission_compartments(self.mission_compartments.clone());
        }
        Ok(domain)
    }
}

pub fn bundled_config_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config")
        .join(name)
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use mim_labeling::{CategoryMarking, ClassificationLevel, ConfidentialityLabel, LabelPolicy};
    use mim_policy::downgraded_label_for_target;

    #[test]
    fn loads_toml_config_and_builds_guard() {
        let path = bundled_config_path("dcs-coalition.toml");
        let config = DcsConfig::load_path(&path).expect("load");
        let guard = config.build_guard().expect("guard");
        assert_eq!(guard.source().id.0, "DOMAIN-HIGH");
        assert_eq!(guard.target().id.0, "DOMAIN-LOW");
    }

    #[test]
    fn downgraded_label_intersects_releasability() {
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec![
                "USA".into(),
                "GBR".into(),
                "DEU".into(),
            ]));
        let target = SecurityDomain::new(
            "DOMAIN-LOW",
            "Low",
            ClassificationLevel::Restricted,
        )
        .with_releasable_to(vec!["USA".into(), "GBR".into()]);
        let downgraded =
            downgraded_label_for_target(&label, &target, &DowngradeConfig::default())
                .expect("downgrade");
        assert_eq!(downgraded.classification, ClassificationLevel::Restricted);
        assert_eq!(downgraded.releasable_countries(), vec!["USA", "GBR"]);
    }

    #[test]
    fn loads_accredited_config_with_worm_audit() {
        let path = bundled_config_path("dcs-accredited.toml");
        let config = DcsConfig::load_path(&path).expect("load");
        assert!(config.is_accredited_profile());
        assert_eq!(config.audit.sink_type, AuditSinkType::Worm);
        config.validate_accredited_profile().expect("valid");
        let guard = config.build_guard().expect("guard");
        assert!(guard.is_accredited());
    }

    #[test]
    fn accredited_rejects_non_worm_sink() {
        let mut config = DcsConfig::conformance_high_to_low();
        config.accredited = true;
        config.audit.path = Some("target/test-audit.jsonl".into());
        config.audit.sink_type = AuditSinkType::File;
        let err = config.validate_accredited_profile().expect_err("worm");
        assert!(err.contains("worm"));
    }
}
