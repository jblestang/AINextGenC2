use serde::{Deserialize, Serialize};

use crate::dimension::{Mip4ComplianceStatus, Mip4Dimension, Mip4DimensionResult, ACCREDITATION_THRESHOLD};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mip4TestResult {
    pub id: String,
    pub suite: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mip4SuiteResult {
    pub name: String,
    pub passed: usize,
    pub failed: usize,
    pub total: usize,
    pub tests: Vec<Mip4TestResult>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mip4ConformanceReport {
    pub overall_score: f64,
    pub is_fully_compliant: bool,
    pub meets_accreditation_threshold: bool,
    pub dimensions: Vec<Mip4DimensionResult>,
    pub suites: Vec<Mip4SuiteResult>,
    pub recommendations: Vec<String>,
}

impl Mip4ConformanceReport {
    pub fn total_passed(&self) -> usize {
        self.suites.iter().map(|s| s.passed).sum()
    }

    pub fn total_failed(&self) -> usize {
        self.suites.iter().map(|s| s.failed).sum()
    }

    pub fn total_tests(&self) -> usize {
        self.suites.iter().map(|s| s.total).sum()
    }

    pub fn dimension(&self, dimension: Mip4Dimension) -> Option<&Mip4DimensionResult> {
        self.dimensions.iter().find(|result| result.dimension == dimension)
    }

    pub fn lowest_dimension_score(&self) -> f64 {
        self.dimensions
            .iter()
            .map(|dimension| dimension.score)
            .fold(f64::INFINITY, f64::min)
    }
}

impl Mip4DimensionResult {
    pub fn is_accredited(&self) -> bool {
        self.score >= ACCREDITATION_THRESHOLD
            && self.status == Mip4ComplianceStatus::Compliant
    }
}
