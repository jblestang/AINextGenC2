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
        }
    }

    pub fn with_releasable_to(mut self, countries: Vec<String>) -> Self {
        self.releasable_to = countries;
        self
    }

    pub fn accepts_country(&self, country: &str) -> bool {
        self.releasable_to.is_empty() || self.releasable_to.iter().any(|c| c == country)
    }

    pub fn validate_id(id: &str) -> LabelResult<()> {
        if id.is_empty() {
            return Err(LabelError::InvalidDomain("domain id must not be empty".into()));
        }
        Ok(())
    }
}
