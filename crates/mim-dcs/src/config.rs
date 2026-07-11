//! Configurable DCS guard — domains, cross-domain policies, and SPIF sources from file.

use std::fs;
use std::path::{Path, PathBuf};

use mim_labeling::{DomainId, SecurityDomain};
use mim_policy::{
    apply_spif_to_store, CrossDomainPolicy, DowngradeConfig, PolicyAdministrationPoint,
    PolicyDecisionPoint, PolicyEnforcementPoint, PolicyInformationPoint, PolicyStore,
};
use mim_spif::SpifRegistry;
use serde::{Deserialize, Serialize};

use crate::guard::CrossDomainGuard;

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
                },
                DomainConfig {
                    id: "DOMAIN-LOW".into(),
                    name: "Low Side".into(),
                    max_classification: "RESTRICTED".into(),
                    releasable_to: vec!["USA".into(), "GBR".into()],
                    accepted_nationalities: vec!["USA".into(), "GBR".into()],
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
            config_dir: None,
        }
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
        let store = self.build_policy_store()?;
        let (source, target) = self.primary_domain_pair()?;
        let pep = PolicyEnforcementPoint::new(
            PolicyInformationPoint::new(),
            PolicyDecisionPoint::new(store),
        );
        Ok(CrossDomainGuard::from_policy_plane(pep, source, target))
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
}
