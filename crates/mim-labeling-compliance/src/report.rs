use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LabelingDimension {
    Stanag4774,
    Stanag4778,
    Ztdf,
    DcsCrossDomain,
    PolicyPlane,
    NatoPolicy,
    AssertionBinding,
    CapcoPolicy,
    UkPolicy,
    SpifIngestion,
    AuditTrail,
    FipsCrypto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LabelingComplianceStatus {
    Compliant,
    Partial,
    NonCompliant,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelingDimensionResult {
    pub dimension: LabelingDimension,
    pub status: LabelingComplianceStatus,
    pub score: f64,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelingComplianceReport {
    pub overall_score: f64,
    pub is_fully_compliant: bool,
    pub dimensions: Vec<LabelingDimensionResult>,
    pub recommendations: Vec<String>,
}

impl LabelingComplianceReport {
    pub fn dimension(&self, dimension: LabelingDimension) -> Option<&LabelingDimensionResult> {
        self.dimensions
            .iter()
            .find(|result| result.dimension == dimension)
    }
}
