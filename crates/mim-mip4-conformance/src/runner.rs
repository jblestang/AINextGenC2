use crate::dimension::{Mip4Dimension, ACCREDITATION_THRESHOLD};
use crate::evaluate::evaluate_dimensions;
use crate::report::{Mip4ConformanceReport, Mip4SuiteResult, Mip4TestResult};

/// Runs the MIP4-IES conformance test suite with per-dimension accreditation scoring.
#[derive(Clone, Debug, Default)]
pub struct Mip4ConformanceRunner;

impl Mip4ConformanceRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self) -> Mip4ConformanceReport {
        let dimensions = evaluate_dimensions();
        let suites: Vec<Mip4SuiteResult> = crate::evaluate::evaluate_legacy_suites()
            .into_iter()
            .map(|(name, tests)| finalize_suite(&name, tests))
            .collect();

        let total = suites.iter().map(|s| s.total).sum::<usize>();
        let passed = suites.iter().map(|s| s.passed).sum::<usize>();
        let overall_score = if total == 0 {
            0.0
        } else {
            passed as f64 / total as f64
        };

        let meets_accreditation_threshold = dimensions.iter().all(|d| d.score >= ACCREDITATION_THRESHOLD);
        let is_fully_compliant = passed == total && total > 0 && meets_accreditation_threshold;

        let mut recommendations = Vec::new();
        for dimension in &dimensions {
            if dimension.score < ACCREDITATION_THRESHOLD {
                recommendations.push(format!(
                    "[{}] {:.0}% — {}",
                    dimension.dimension.label(),
                    dimension.score * 100.0,
                    dimension.message
                ));
            }
        }
        for suite in &suites {
            for test in &suite.tests {
                if !test.passed {
                    recommendations.push(format!(
                        "[{}] {}: {}",
                        suite.name, test.id, test.message
                    ));
                }
            }
        }
        if recommendations.is_empty() {
            recommendations.push(format!(
                "All MIP4-IES dimensions meet the {:.0}% accreditation threshold.",
                ACCREDITATION_THRESHOLD * 100.0
            ));
        }

        Mip4ConformanceReport {
            overall_score,
            is_fully_compliant,
            meets_accreditation_threshold,
            dimensions,
            suites,
            recommendations,
        }
    }
}

fn finalize_suite(name: &str, tests: Vec<Mip4TestResult>) -> Mip4SuiteResult {
    let passed = tests.iter().filter(|test| test.passed).count();
    let total = tests.len();
    Mip4SuiteResult {
        name: name.to_owned(),
        passed,
        failed: total.saturating_sub(passed),
        total,
        tests,
    }
}
