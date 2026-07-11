use mim_labeling::{ClassificationLevel, ConfidentialityLabel, DomainId};
use serde::{Deserialize, Serialize};

/// Access operation requested against a labeled resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccessOperation {
    Read,
    Write,
    Delete,
    CrossDomainTransfer,
}

/// Subject (requester) attributes supplied by the PIP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectAttributes {
    pub subject_id: String,
    pub clearance: ClassificationLevel,
    pub nationality: Option<String>,
    /// Handling caveats held by the subject (STANAG 4774 restrictive categories).
    #[serde(default)]
    pub handling_caveats: Vec<String>,
    /// Active mission compartment for compartmented operations.
    #[serde(default)]
    pub mission_id: Option<String>,
}

impl SubjectAttributes {
    pub fn new(subject_id: impl Into<String>, clearance: ClassificationLevel) -> Self {
        Self {
            subject_id: subject_id.into(),
            clearance,
            nationality: None,
            handling_caveats: Vec::new(),
            mission_id: None,
        }
    }

    pub fn with_nationality(mut self, nationality: impl Into<String>) -> Self {
        self.nationality = Some(nationality.into());
        self
    }

    pub fn with_handling_caveats(mut self, caveats: Vec<String>) -> Self {
        self.handling_caveats = caveats;
        self
    }

    pub fn with_handling_caveat(mut self, caveat: impl Into<String>) -> Self {
        self.handling_caveats.push(caveat.into());
        self
    }

    pub fn with_mission_id(mut self, mission_id: impl Into<String>) -> Self {
        self.mission_id = Some(mission_id.into());
        self
    }

    pub fn holds_caveat(&self, caveat: &str) -> bool {
        self.handling_caveats
            .iter()
            .any(|held| held.eq_ignore_ascii_case(caveat))
    }
}

/// Resource attributes derived from a confidentiality label.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAttributes {
    pub classification: ClassificationLevel,
    pub releasable_countries: Vec<String>,
    pub policy_id: String,
    /// Restrictive handling caveats on the labeled resource.
    #[serde(default)]
    pub handling_caveats: Vec<String>,
}

impl ResourceAttributes {
    pub fn from_label(label: &ConfidentialityLabel) -> Self {
        Self {
            classification: label.classification,
            releasable_countries: label.releasable_countries(),
            policy_id: label.policy.identifier.clone(),
            handling_caveats: label.restrictive_category_values(),
        }
    }
}

/// Environment attributes for policy evaluation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentAttributes {
    pub operation: AccessOperation,
    pub source_domain: DomainId,
    pub target_domain: Option<DomainId>,
    pub mission_id: Option<String>,
}

impl EnvironmentAttributes {
    pub fn local(operation: AccessOperation, domain: DomainId) -> Self {
        Self {
            operation,
            source_domain: domain,
            target_domain: None,
            mission_id: None,
        }
    }

    pub fn cross_domain(
        source: DomainId,
        target: DomainId,
        mission_id: Option<String>,
    ) -> Self {
        Self {
            operation: AccessOperation::CrossDomainTransfer,
            source_domain: source,
            target_domain: Some(target),
            mission_id,
        }
    }
}

/// Full policy evaluation context assembled by the PIP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyContext {
    pub subject: SubjectAttributes,
    pub resource: ResourceAttributes,
    pub environment: EnvironmentAttributes,
    pub label: ConfidentialityLabel,
}
