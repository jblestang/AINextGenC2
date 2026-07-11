use serde::{Deserialize, Serialize};

use crate::classification::ClassificationLevel;
use crate::error::{LabelError, LabelResult};

/// Identifier for a security domain in a cross-domain solution.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainId(pub String);

impl DomainId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

/// A security enclave with maximum classification and releasability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityDomain {
    pub id: DomainId,
    pub name: String,
    pub max_classification: ClassificationLevel,
    pub releasable_to: Vec<String>,
    #[serde(default)]
    pub accepted_nationalities: Vec<String>,
    /// Mission compartments authorized in this domain (cross-domain transfers require matching `mission_id`).
    #[serde(default)]
    pub mission_compartments: Vec<String>,
}

impl SecurityDomain {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        max_classification: ClassificationLevel,
    ) -> Self {
        Self {
            id: DomainId::new(id),
            name: name.into(),
            max_classification,
            releasable_to: Vec::new(),
            accepted_nationalities: Vec::new(),
            mission_compartments: Vec::new(),
        }
    }

    pub fn with_mission_compartments(mut self, missions: Vec<String>) -> Self {
        self.mission_compartments = missions;
        self
    }

    pub fn accepts_mission(&self, mission_id: &str) -> bool {
        self.mission_compartments.is_empty()
            || self
                .mission_compartments
                .iter()
                .any(|m| m.eq_ignore_ascii_case(mission_id))
    }

    pub fn with_accepted_nationalities(mut self, nationalities: Vec<String>) -> Self {
        self.accepted_nationalities = nationalities;
        self
    }

    pub fn with_releasable_to(mut self, countries: Vec<String>) -> Self {
        self.releasable_to = countries;
        self
    }

    pub fn accepts_country(&self, country: &str) -> bool {
        if !self.accepted_nationalities.is_empty()
            && !self
                .accepted_nationalities
                .iter()
                .any(|c| c.eq_ignore_ascii_case(country))
        {
            return false;
        }
        self.releasable_to.is_empty()
            || self
                .releasable_to
                .iter()
                .any(|c| c.eq_ignore_ascii_case(country))
    }

    pub fn validate_id(id: &str) -> LabelResult<()> {
        if id.is_empty() {
            return Err(LabelError::InvalidDomain("domain id must not be empty".into()));
        }
        Ok(())
    }
}
