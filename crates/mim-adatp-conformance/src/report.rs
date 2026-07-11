use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdatpTestResult {
    pub id: String,
    pub suite: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdatpSuiteResult {
    pub name: String,
    pub passed: usize,
    pub failed: usize,
    pub total: usize,
    pub tests: Vec<AdatpTestResult>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdatpConformanceReport {
    pub overall_score: f64,
    pub is_fully_compliant: bool,
    pub suites: Vec<AdatpSuiteResult>,
    pub recommendations: Vec<String>,
}

impl AdatpConformanceReport {
    pub fn total_passed(&self) -> usize {
        self.suites.iter().map(|s| s.passed).sum()
    }

    pub fn total_failed(&self) -> usize {
        self.suites.iter().map(|s| s.failed).sum()
    }

    pub fn total_tests(&self) -> usize {
        self.suites.iter().map(|s| s.total).sum()
    }
}
