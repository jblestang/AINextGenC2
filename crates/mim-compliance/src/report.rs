use serde::{Deserialize, Serialize};

/// Compliance dimension evaluated by the checker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceDimension {
    ModelCoverage,
    SemanticIds,
    NilReason,
    Metadata,
    RepresentationTerms,
    Validation,
    Serialization,
    ZeroPanic,
}

/// Status for a compliance dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ComplianceStatus {
    Compliant,
    Partial,
    NonCompliant,
}

/// Finding for a single compliance dimension.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DimensionResult {
    pub dimension: ComplianceDimension,
    pub status: ComplianceStatus,
    pub score: f64,
    pub message: String,
}

/// Full compliance report for a MIM stack evaluation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReport {
    pub target_version: String,
    pub loaded_version: String,
    pub overall_score: f64,
    pub is_fully_compliant: bool,
    pub dimensions: Vec<DimensionResult>,
    pub recommendations: Vec<String>,
}

impl ComplianceReport {
    pub fn dimension(&self, dimension: ComplianceDimension) -> Option<&DimensionResult> {
        self.dimensions
            .iter()
            .find(|result| result.dimension == dimension)
    }
}
