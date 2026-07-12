//! FMN-style LDAP subject directory for identity-bound policy.
//!
//! Coalition exercises use a fixture-backed directory (TOML entries) that models
//! NATO LDAP clearance attributes. Live LDAP URL configuration is recorded for
//! operational deployment; resolution uses bundled entries in lab mode.

use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use mim_labeling::ClassificationLevel;
use serde::Deserialize;

use crate::context::SubjectAttributes;
use crate::error::{PolicyError, PolicyResult};

/// FMN coalition LDAP server configuration (ADatP / FMN Spiral style).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct LdapServerConfig {
    pub server: String,
    pub base_dn: String,
    #[serde(default)]
    pub bind_dn: Option<String>,
    #[serde(default)]
    pub search_filter: Option<String>,
    #[serde(default = "default_fixture_mode")]
    pub fixture_mode: bool,
}

fn default_fixture_mode() -> bool {
    true
}

/// Root LDAP PIP configuration file (`config/fmn-ldap-pip.toml`).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct LdapPipConfig {
    pub ldap: LdapServerConfig,
    #[serde(default)]
    pub entries_file: Option<String>,
    #[serde(default)]
    pub cert_mappings: Vec<CertSubjectMapping>,
    #[serde(default)]
    pub cert_fingerprint_mappings: Vec<CertFingerprintMapping>,
    #[serde(default)]
    pub default_domain_id: Option<String>,
}

/// Maps an mTLS client certificate CN to an LDAP principal.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CertSubjectMapping {
    pub cn: String,
    pub principal: String,
}

/// Maps a client certificate SHA-256 fingerprint (hex) to an LDAP principal.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CertFingerprintMapping {
    pub cert_sha256: String,
    pub principal: String,
}

/// One LDAP directory entry (NATO structured clearance attributes).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct LdapSubjectEntry {
    pub principal: String,
    pub subject_id: String,
    pub clearance: String,
    #[serde(default)]
    pub nationality: Option<String>,
    #[serde(default)]
    pub handling_caveats: Vec<String>,
    #[serde(default)]
    pub mission_id: Option<String>,
}

/// Fixture-backed LDAP subject directory.
#[derive(Clone, Debug)]
pub struct LdapSubjectDirectory {
    config: LdapPipConfig,
    entries: IndexMap<String, LdapSubjectEntry>,
    cert_to_principal: IndexMap<String, String>,
    fingerprint_to_principal: IndexMap<String, String>,
}

impl LdapSubjectDirectory {
    pub fn from_config(config: LdapPipConfig, entries: Vec<LdapSubjectEntry>) -> PolicyResult<Self> {
        let mut index = IndexMap::new();
        for entry in entries {
            index.insert(normalize_principal(&entry.principal), entry);
        }
        let mut cert_to_principal = IndexMap::new();
        for mapping in &config.cert_mappings {
            cert_to_principal.insert(mapping.cn.clone(), mapping.principal.clone());
        }
        let mut fingerprint_to_principal = IndexMap::new();
        for mapping in &config.cert_fingerprint_mappings {
            fingerprint_to_principal.insert(
                mapping.cert_sha256.to_ascii_lowercase(),
                mapping.principal.clone(),
            );
        }
        Ok(Self {
            config,
            entries: index,
            cert_to_principal,
            fingerprint_to_principal,
        })
    }

    pub fn load_path(path: impl AsRef<Path>) -> PolicyResult<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| {
            PolicyError::Invalid(format!("read LDAP PIP config {}: {e}", path.display()))
        })?;
        let config: LdapPipConfig = toml::from_str(&content).map_err(|e| {
            PolicyError::Invalid(format!("parse LDAP PIP config {}: {e}", path.display()))
        })?;
        Self::load_config(&config, path.parent())
    }

    pub fn load_config(
        config: &LdapPipConfig,
        base_dir: Option<&Path>,
    ) -> PolicyResult<Self> {
        let entries_path = config
            .entries_file
            .as_ref()
            .map(|relative| resolve_relative_path(base_dir, relative))
            .unwrap_or_else(|| {
                base_dir
                    .map(|dir| dir.join("fmn-ldap-entries.toml"))
                    .unwrap_or_else(|| PathBuf::from("config/fmn-ldap-entries.toml"))
            });
        let entries_content = std::fs::read_to_string(&entries_path).map_err(|e| {
            PolicyError::Invalid(format!(
                "read LDAP entries {}: {e}",
                entries_path.display()
            ))
        })?;
        let entries_file: LdapEntriesFile = toml::from_str(&entries_content).map_err(|e| {
            PolicyError::Invalid(format!(
                "parse LDAP entries {}: {e}",
                entries_path.display()
            ))
        })?;
        Self::from_config(config.clone(), entries_file.entries)
    }

    pub fn conformance() -> PolicyResult<Self> {
        let config = LdapPipConfig {
            ldap: LdapServerConfig {
                server: "ldap://fmn-nato-exercise.mil".into(),
                base_dn: "ou=operators,dc=nato,dc=int".into(),
                bind_dn: None,
                search_filter: Some("(uid={principal})".into()),
                fixture_mode: true,
            },
            entries_file: None,
            cert_mappings: vec![
                CertSubjectMapping {
                    cn: "usa-analyst.nato.mil".into(),
                    principal: "uid=usa-analyst,ou=USA,ou=operators,dc=nato,dc=int".into(),
                },
                CertSubjectMapping {
                    cn: "gbr-analyst.nato.mil".into(),
                    principal: "uid=gbr-analyst,ou=GBR,ou=operators,dc=nato,dc=int".into(),
                },
            ],
            cert_fingerprint_mappings: vec![],
            default_domain_id: Some("DOMAIN-HIGH".into()),
        };
        let entries = vec![
            LdapSubjectEntry {
                principal: "uid=usa-analyst,ou=USA,ou=operators,dc=nato,dc=int".into(),
                subject_id: "usa-analyst".into(),
                clearance: "SECRET".into(),
                nationality: Some("USA".into()),
                handling_caveats: vec![],
                mission_id: None,
            },
            LdapSubjectEntry {
                principal: "uid=gbr-analyst,ou=GBR,ou=operators,dc=nato,dc=int".into(),
                subject_id: "gbr-analyst".into(),
                clearance: "SECRET".into(),
                nationality: Some("GBR".into()),
                handling_caveats: vec![],
                mission_id: None,
            },
            LdapSubjectEntry {
                principal: "uid=deu-analyst,ou=DEU,ou=operators,dc=nato,dc=int".into(),
                subject_id: "deu-analyst".into(),
                clearance: "SECRET".into(),
                nationality: Some("DEU".into()),
                handling_caveats: vec![],
                mission_id: None,
            },
        ];
        Self::from_config(config, entries)
    }

    pub fn config(&self) -> &LdapPipConfig {
        &self.config
    }

    pub fn default_domain_id(&self) -> Option<&str> {
        self.config.default_domain_id.as_deref()
    }

    /// Resolve a directory principal (LDAP DN or uid) to subject attributes.
    pub fn resolve_principal(&self, principal: &str) -> PolicyResult<SubjectAttributes> {
        let normalized = normalize_principal(principal);
        let entry = self
            .entries
            .get(&normalized)
            .or_else(|| self.entries.values().find(|e| e.subject_id == normalized))
            .ok_or_else(|| {
                PolicyError::NotFound(format!(
                    "LDAP principal '{principal}' not found in fixture directory"
                ))
            })?;
        entry.to_subject_attributes()
    }

    /// Resolve an mTLS client certificate CN to subject attributes.
    pub fn resolve_cert_cn(&self, cn: &str) -> PolicyResult<SubjectAttributes> {
        let principal = self
            .cert_to_principal
            .get(cn)
            .cloned()
            .unwrap_or_else(|| format!("uid={cn},ou=operators,dc=nato,dc=int"));
        self.resolve_principal(&principal)
    }

    /// Resolve an mTLS client certificate SHA-256 fingerprint to subject attributes.
    pub fn resolve_cert_fingerprint(&self, fingerprint: &str) -> PolicyResult<SubjectAttributes> {
        let normalized = fingerprint.trim().to_ascii_lowercase();
        let principal = self
            .fingerprint_to_principal
            .get(&normalized)
            .ok_or_else(|| {
                PolicyError::NotFound(format!(
                    "certificate fingerprint '{fingerprint}' not registered in LDAP directory"
                ))
            })?;
        self.resolve_principal(principal)
    }

    pub fn resolve_cert_cn_or_principal(&self, identity: &str) -> PolicyResult<SubjectAttributes> {
        if self.cert_to_principal.contains_key(identity) {
            return self.resolve_cert_cn(identity);
        }
        if self.entries.contains_key(&normalize_principal(identity))
            || self.entries.values().any(|e| e.subject_id == identity)
        {
            return self.resolve_principal(identity);
        }
        self.resolve_cert_cn(identity)
    }
}

impl LdapSubjectEntry {
    pub fn to_subject_attributes(&self) -> PolicyResult<SubjectAttributes> {
        let clearance = parse_clearance(&self.clearance)?;
        let mut subject = SubjectAttributes::new(&self.subject_id, clearance);
        if let Some(nationality) = &self.nationality {
            subject = subject.with_nationality(nationality);
        }
        for caveat in &self.handling_caveats {
            subject = subject.with_handling_caveat(caveat);
        }
        if let Some(mission_id) = &self.mission_id {
            subject = subject.with_mission_id(mission_id);
        }
        Ok(subject)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct LdapEntriesFile {
    entries: Vec<LdapSubjectEntry>,
}

fn parse_clearance(value: &str) -> PolicyResult<ClassificationLevel> {
    ClassificationLevel::parse(value).map_err(PolicyError::from)
}

fn normalize_principal(principal: &str) -> String {
    principal.trim().to_ascii_lowercase()
}

fn resolve_relative_path(base_dir: Option<&Path>, relative: &str) -> PathBuf {
    let path = PathBuf::from(relative);
    if path.is_absolute() {
        return path;
    }
    base_dir
        .map(|dir| dir.join(&path))
        .unwrap_or(path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn conformance_directory_resolves_usa_and_gbr() {
        let dir = LdapSubjectDirectory::conformance().expect("dir");
        let usa = dir
            .resolve_cert_cn("usa-analyst.nato.mil")
            .expect("usa");
        assert_eq!(usa.subject_id, "usa-analyst");
        assert_eq!(usa.nationality.as_deref(), Some("USA"));
        let gbr = dir
            .resolve_cert_cn("gbr-analyst.nato.mil")
            .expect("gbr");
        assert_eq!(gbr.nationality.as_deref(), Some("GBR"));
    }

    #[test]
    fn loads_config_from_workspace_files() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/fmn-ldap-pip.toml");
        if path.exists() {
            let dir = LdapSubjectDirectory::load_path(&path).expect("load");
            let entry = dir.resolve_principal("usa-sensor-operator").expect("resolve");
            assert_eq!(entry.nationality.as_deref(), Some("USA"));
        }
    }
}
