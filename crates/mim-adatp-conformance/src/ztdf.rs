use mim_labeling::{CategoryMarking, ClassificationLevel, ConfidentialityLabel, LabelPolicy};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use mim_ztdf::ZtdfPackage;

use crate::report::{AdatpSuiteResult, AdatpTestResult};

pub fn run_ztdf_suite(secret: &[u8]) -> AdatpSuiteResult {
    let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
        .with_category(CategoryMarking::releasable_to(vec!["USA".into(), "GBR".into()]));
    let payload = br#"{"modelVersion":"5.1.0","instances":[]}"#.to_vec();

    let package = ZtdfPackage::create(&label, payload.clone(), secret);
    let verify = package
        .as_ref()
        .map(|p| p.verify(secret).is_ok())
        .unwrap_or(false);

    let manifest = package.as_ref().ok().and_then(|p| p.manifest_json().ok());
    let has_nato_assertion = manifest
        .as_ref()
        .map(|m: &String| m.contains("nato-label-1"))
        .unwrap_or(false);
    let has_4774_schema = manifest
        .as_ref()
        .map(|m: &String| m.contains("urn:nato:stanag:4774:confidentialitymetadatalabel:1:0"))
        .unwrap_or(false);

    let codec = Stanag4774Codec::new();
    let assertion_label = package.as_ref().ok().and_then(|p| {
        p.manifest
            .nato_label_assertion()
            .and_then(|a| serde_json::to_string(&a.statement.value).ok())
            .and_then(|json| codec.deserialize(&json, Stanag4774Format::JsonStructured).ok())
    });

    let tests = vec![
        AdatpTestResult {
            id: "ztdf-package-create".into(),
            suite: "ZTDF/ACP-240".into(),
            passed: package.is_ok(),
            message: "ZTDF package created with encrypted payload reference".into(),
        },
        AdatpTestResult {
            id: "ztdf-package-verify".into(),
            suite: "ZTDF/ACP-240".into(),
            passed: verify,
            message: "ZTDF package binding verification passes".into(),
        },
        AdatpTestResult {
            id: "ztdf-nato-assertion".into(),
            suite: "ZTDF/ACP-240".into(),
            passed: has_nato_assertion,
            message: "Manifest contains mandatory nato-label-1 assertion".into(),
        },
        AdatpTestResult {
            id: "ztdf-4774-schema".into(),
            suite: "ZTDF/ACP-240".into(),
            passed: has_4774_schema,
            message: "Assertion uses STANAG 4774 schema URI".into(),
        },
        AdatpTestResult {
            id: "ztdf-assertion-label-parse".into(),
            suite: "ZTDF/ACP-240".into(),
            passed: assertion_label.is_some(),
            message: "Embedded STANAG 4774 label in assertion parses".into(),
        },
    ];

    let passed = tests.iter().filter(|t| t.passed).count();
    AdatpSuiteResult {
        name: "ZTDF / OpenTDF (ACP-240)".to_owned(),
        passed,
        failed: tests.len().saturating_sub(passed),
        total: tests.len(),
        tests,
    }
}
