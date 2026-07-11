use serde::{Deserialize, Serialize};

/// MIP4-IES FMN accreditation dimensions (target ≥95% each).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mip4Dimension {
    RestOperations,
    RestBinding,
    MessageSchemas,
    Replication,
    MimSemantics,
    FmnSecurity,
    Accreditation,
}

impl Mip4Dimension {
    pub const ALL: &'static [Self] = &[
        Self::RestOperations,
        Self::RestBinding,
        Self::MessageSchemas,
        Self::Replication,
        Self::MimSemantics,
        Self::FmnSecurity,
        Self::Accreditation,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::RestOperations => "REST operations",
            Self::RestBinding => "REST binding",
            Self::MessageSchemas => "Message schemas",
            Self::Replication => "Replication",
            Self::MimSemantics => "MIM semantics",
            Self::FmnSecurity => "FMN security",
            Self::Accreditation => "Accreditation",
        }
    }
}

/// FMN accreditation threshold per dimension.
pub const ACCREDITATION_THRESHOLD: f64 = 0.95;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mip4ComplianceStatus {
    Compliant,
    Partial,
    NonCompliant,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mip4DimensionResult {
    pub dimension: Mip4Dimension,
    pub status: Mip4ComplianceStatus,
    pub score: f64,
    pub message: String,
    pub tests_passed: usize,
    pub tests_total: usize,
}

impl Mip4DimensionResult {
    pub fn from_tests(dimension: Mip4Dimension, passed: usize, total: usize, message: impl Into<String>) -> Self {
        let score = if total == 0 {
            0.0
        } else {
            passed as f64 / total as f64
        };
        let status = if score >= ACCREDITATION_THRESHOLD {
            Mip4ComplianceStatus::Compliant
        } else if score >= 0.75 {
            Mip4ComplianceStatus::Partial
        } else {
            Mip4ComplianceStatus::NonCompliant
        };
        Self {
            dimension,
            status,
            score,
            message: message.into(),
            tests_passed: passed,
            tests_total: total,
        }
    }
}
