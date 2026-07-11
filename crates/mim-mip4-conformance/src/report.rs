use serde::{Deserialize, Serialize};

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
}
