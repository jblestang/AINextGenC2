use chrono::{DateTime, Utc};
use mim_core::{Nillable, NilReason};
use serde::{Deserialize, Serialize};

/// Reporter metadata for exchanged information.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Reporter {
    pub name: Nillable<String>,
    pub role: Nillable<String>,
    pub organisation: Nillable<String>,
}

/// Observer metadata.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Observer {
    pub name: Nillable<String>,
    pub role: Nillable<String>,
}

/// Operational/intelligence appraisal metadata.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OperationalAppraisal {
    pub confidence: Nillable<String>,
    pub credibility: Nillable<String>,
    pub reliability: Nillable<String>,
}

/// Temporal validity of information.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityPeriod {
    pub start: Nillable<DateTime<Utc>>,
    pub end: Nillable<DateTime<Utc>>,
}

impl Default for ValidityPeriod {
    fn default() -> Self {
        Self {
            start: Nillable::Absent,
            end: Nillable::Absent,
        }
    }
}

/// Security classification metadata.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityClassification {
    pub policy: Nillable<String>,
    pub classification: Nillable<String>,
    pub releasability: Nillable<String>,
}

/// MIM Metadata aggregate attached to objects and actions.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Metadata {
    pub reporter: Reporter,
    pub observer: Observer,
    pub appraisal: OperationalAppraisal,
    pub validity: ValidityPeriod,
    pub security: SecurityClassification,
}

impl Metadata {
    pub fn with_withheld_classification() -> Self {
        Self {
            security: SecurityClassification {
                classification: Nillable::nil(NilReason::Withheld),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_supports_nil_security_classification() {
        let meta = Metadata::with_withheld_classification();
        assert!(!meta.security.classification.is_present());
    }
}
