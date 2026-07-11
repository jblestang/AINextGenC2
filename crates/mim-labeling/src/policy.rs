use serde::{Deserialize, Serialize};

use crate::classification::ClassificationLevel;

/// Governing security policy for a confidentiality label.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelPolicy {
    pub identifier: String,
    pub oid: Option<String>,
    pub allowed_classifications: Vec<ClassificationLevel>,
}

impl LabelPolicy {
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            oid: None,
            allowed_classifications: ClassificationLevel::ALL.to_vec(),
        }
    }

    pub fn with_identifier(mut self, identifier: impl Into<String>) -> Self {
        self.identifier = identifier.into();
        self
    }

    pub fn with_oid(mut self, oid: impl Into<String>) -> Self {
        self.oid = Some(oid.into());
        self
    }

    pub fn with_allowed_classifications(mut self, levels: Vec<ClassificationLevel>) -> Self {
        self.allowed_classifications = levels;
        self
    }

    pub fn allows_classification(&self, level: ClassificationLevel) -> bool {
        self.allowed_classifications.contains(&level)
    }
}

/// NATO security policy profile (STANAG 4774 Annex B reference).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NatoPolicy;

impl NatoPolicy {
    pub const POLICY_OID: &'static str =
        "urn:oid:2.16.840.1.101.2.3.6.1.31778.102.25";

    pub fn policy() -> LabelPolicy {
        LabelPolicy::new("NATO")
            .with_oid(Self::POLICY_OID)
            .with_allowed_classifications(vec![
                ClassificationLevel::Unclassified,
                ClassificationLevel::Restricted,
                ClassificationLevel::Confidential,
                ClassificationLevel::Secret,
                ClassificationLevel::CosmicTopSecret,
            ])
    }

    pub fn public_policy() -> LabelPolicy {
        LabelPolicy::new("PUBLIC")
            .with_allowed_classifications(vec![
                ClassificationLevel::Unmarked,
                ClassificationLevel::Unclassified,
            ])
    }
}

impl LabelPolicy {
    pub fn nato() -> Self {
        NatoPolicy::policy()
    }

    pub fn public_day_zero() -> Self {
        NatoPolicy::public_policy()
    }
}
