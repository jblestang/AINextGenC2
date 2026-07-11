use mim_crypto::conformance_keypair;
use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use mim_stanag4778::{AssertionBinding, BindingDataObject};

use crate::acme::{acme_invalid_label, acme_valid_label, validate_acme_semantics};
use crate::report::{AdatpConformanceReport, AdatpSuiteResult, AdatpTestResult};
use crate::vectors::ADATP_VECTORS;
use crate::ztdf::run_ztdf_suite;

/// Runs the NATO ADatP conformance test suite.
#[derive(Clone, Debug, Default)]
pub struct AdatpConformanceRunner;

impl AdatpConformanceRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self) -> AdatpConformanceReport {
        let suites = vec![
            self.suite_adatp_4774_table17(),
            self.suite_adatp_4774_annex_b_roundtrip(),
            self.suite_adatp_4774_1_acme(),
            self.suite_adatp_4778_binding(),
            self.suite_spif_policies(),
            run_ztdf_suite(),
        ];

        let total = suites.iter().map(|s| s.total).sum::<usize>();
        let passed = suites.iter().map(|s| s.passed).sum::<usize>();
        let overall_score = if total == 0 {
            0.0
        } else {
            passed as f64 / total as f64
        };
        let is_fully_compliant = passed == total && total > 0;

        let mut recommendations = Vec::new();
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
            recommendations.push(
                "All NATO ADatP conformance test vectors passed.".into(),
            );
        }

        AdatpConformanceReport {
            overall_score,
            is_fully_compliant,
            suites,
            recommendations,
        }
    }

    fn suite_adatp_4774_table17(&self) -> AdatpSuiteResult {
        let codec = Stanag4774Codec::new();
        let mut tests = Vec::new();

        for vector in ADATP_VECTORS {
            let result = codec.deserialize(vector.xml, Stanag4774Format::Xml);
            let passed = if vector.expect_valid {
                result.is_ok()
            } else {
                result.is_err()
            };
            tests.push(AdatpTestResult {
                id: vector.id.to_owned(),
                suite: "ADatP-4774 Table 17".to_owned(),
                passed,
                message: if passed {
                    vector.description.to_owned()
                } else if vector.expect_valid {
                    result.err().map(|e| e.to_string()).unwrap_or_default()
                } else {
                    "expected invalid label but parsed successfully".into()
                },
            });
        }

        Self::finalize_suite("ADatP-4774 Table 17 (spiffing reference)", tests)
    }

    fn suite_adatp_4774_annex_b_roundtrip(&self) -> AdatpSuiteResult {
        let codec = Stanag4774Codec::new();
        let mut tests = Vec::new();

        for vector in ADATP_VECTORS {
            if !vector.expect_valid {
                continue;
            }
            let parsed = match codec.deserialize(vector.xml, Stanag4774Format::Xml) {
                Ok(label) => label,
                Err(err) => {
                    tests.push(AdatpTestResult {
                        id: format!("{}-roundtrip", vector.id),
                        suite: "ADatP-4774 Annex B".to_owned(),
                        passed: false,
                        message: err.to_string(),
                    });
                    continue;
                }
            };
            let roundtrip = codec.round_trip(&parsed, Stanag4774Format::Xml);
            tests.push(AdatpTestResult {
                id: format!("{}-roundtrip", vector.id),
                suite: "ADatP-4774 Annex B".to_owned(),
                passed: roundtrip.is_ok(),
                message: if roundtrip.is_ok() {
                    "XML round-trip preserves label semantics".into()
                } else {
                    roundtrip.err().map(|e| e.to_string()).unwrap_or_default()
                },
            });
        }

        Self::finalize_suite("ADatP-4774 Annex B round-trip", tests)
    }

    fn suite_adatp_4774_1_acme(&self) -> AdatpSuiteResult {
        let codec = Stanag4774Codec::new();
        let valid_xml = include_str!("../fixtures/adatp/acme-valid-4774.1.xml");
        let invalid_xml = include_str!("../fixtures/adatp/acme-invalid-4774.1.xml");

        let valid_parse = codec.deserialize(valid_xml, Stanag4774Format::Xml);
        let invalid_parse = codec.deserialize(invalid_xml, Stanag4774Format::Xml);

        let valid_sem = valid_parse
            .as_ref()
            .map(|l| validate_acme_semantics(l).is_ok())
            .unwrap_or(false);
        let invalid_sem = invalid_parse
            .as_ref()
            .map(|l| validate_acme_semantics(l).is_err())
            .unwrap_or(false);

        let model_valid = validate_acme_semantics(&acme_valid_label()).is_ok();
        let model_invalid = validate_acme_semantics(&acme_invalid_label()).is_err();

        let tests = vec![
            AdatpTestResult {
                id: "acme-figure7-parse".into(),
                suite: "ADatP-4774.1 ACME".into(),
                passed: valid_parse.is_ok(),
                message: "Figure 7 valid ACME label parses".into(),
            },
            AdatpTestResult {
                id: "acme-figure7-semantic".into(),
                suite: "ADatP-4774.1 ACME".into(),
                passed: valid_sem,
                message: "Figure 7 valid ACME label passes SPIF semantic rules".into(),
            },
            AdatpTestResult {
                id: "acme-figure9-reject".into(),
                suite: "ADatP-4774.1 ACME".into(),
                passed: invalid_sem,
                message: "Figure 9 invalid CONFIDENTIAL label rejected by SPIF rules".into(),
            },
            AdatpTestResult {
                id: "acme-model-valid".into(),
                suite: "ADatP-4774.1 ACME".into(),
                passed: model_valid,
                message: "ACME INTERNAL + Sensitive RED accepted".into(),
            },
            AdatpTestResult {
                id: "acme-model-invalid".into(),
                suite: "ADatP-4774.1 ACME".into(),
                passed: model_invalid,
                message: "ACME CONFIDENTIAL without Releasable To MOCK/PHONY rejected".into(),
            },
        ];

        Self::finalize_suite("ADatP-4774.1 ACME SPIF", tests)
    }

    fn suite_adatp_4778_binding(&self) -> AdatpSuiteResult {
        let keys = conformance_keypair().expect("keys");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let payload = br#"{"modelVersion":"5.1.0","instances":[]}"#;

        let assertion = AssertionBinding::create(&label, payload, keys.signing_key());
        let bdo_embedded = BindingDataObject::embedded(label.clone(), payload);
        let bdo_xml = BindingDataObject::xml_embedded(label.clone(), payload);
        let bdo_encap = BindingDataObject::encapsulated(label.clone(), payload);
        let bdo_detached = BindingDataObject::detached(label.clone(), payload, "label.xml");
        let bdo_assertion =
            BindingDataObject::assertion_bound(label, payload, keys.signing_key());

        let verify_assertion = assertion
            .as_ref()
            .map(|b| b.verify(payload, keys.verifying_key()).is_ok())
            .unwrap_or(false);
        let verify_bdo = bdo_assertion
            .as_ref()
            .map(|b| b.verify(payload, Some(keys.verifying_key())).is_ok())
            .unwrap_or(false);
        let tamper_fails = assertion
            .as_ref()
            .map(|b| b.verify(b"tampered", keys.verifying_key()).is_err())
            .unwrap_or(false);

        let tests = vec![
            AdatpTestResult {
                id: "4778-assertion-create".into(),
                suite: "ADatP-4778".into(),
                passed: assertion.is_ok(),
                message: "NMBS Set: RSA-PSS-SHA256 assertion binding created".into(),
            },
            AdatpTestResult {
                id: "4778-assertion-verify".into(),
                suite: "ADatP-4778".into(),
                passed: verify_assertion,
                message: "NMBS Verify: assertion binding verified".into(),
            },
            AdatpTestResult {
                id: "4778-embedded-bdo".into(),
                suite: "ADatP-4778".into(),
                passed: bdo_embedded.is_ok()
                    && bdo_embedded
                        .as_ref()
                        .map(|b| b.verify(payload, None).is_ok())
                        .unwrap_or(false),
                message: "ADatP-4778.2 JSON sidecar embedded BDO with digest".into(),
            },
            AdatpTestResult {
                id: "4778-xml-embedded-bdo".into(),
                suite: "ADatP-4778".into(),
                passed: bdo_xml.is_ok(),
                message: "ADatP-4778.2 XML embedded BDO".into(),
            },
            AdatpTestResult {
                id: "4778-encapsulated-bdo".into(),
                suite: "ADatP-4778".into(),
                passed: bdo_encap.is_ok(),
                message: "ADatP-4778.2 encapsulated BDO".into(),
            },
            AdatpTestResult {
                id: "4778-detached-bdo".into(),
                suite: "ADatP-4778".into(),
                passed: bdo_detached.is_ok(),
                message: "ADatP-4778.2 detached BDO".into(),
            },
            AdatpTestResult {
                id: "4778-assertion-bdo".into(),
                suite: "ADatP-4778".into(),
                passed: bdo_assertion.is_ok() && verify_bdo,
                message: "ADatP-4778.2 ZTDF assertion binding profile".into(),
            },
            AdatpTestResult {
                id: "4778-tamper-detect".into(),
                suite: "ADatP-4778".into(),
                passed: tamper_fails,
                message: "NMBS binding detects payload tampering".into(),
            },
        ];

        Self::finalize_suite("ADatP-4778 Metadata Binding", tests)
    }

    fn suite_spif_policies(&self) -> AdatpSuiteResult {
        let mut registry = mim_spif::SpifRegistry::new();
        let fixtures = [
            ("acme-policy.xml", include_str!("../fixtures/spif/acme-policy.xml")),
            (
                "nato-4774-policy.xml",
                include_str!("../fixtures/spif/nato-4774-policy.xml"),
            ),
            (
                "capco-us-policy.xml",
                include_str!("../fixtures/spif/capco-us-policy.xml"),
            ),
            ("uk-demo.xml", include_str!("../fixtures/spif/uk-demo.xml")),
        ];
        let mut tests = Vec::new();
        for (id, xml) in fixtures {
            let load_ok = registry.load_xml(xml).is_ok();
            tests.push(AdatpTestResult {
                id: format!("spif-load-{id}"),
                suite: "XML-SPIF".into(),
                passed: load_ok,
                message: format!("SPIF policy {id} ingested"),
            });
        }
        let validator = mim_spif::SpifValidator::new(registry);
        let uk_secret = ConfidentialityLabel::new(LabelPolicy::new("DEMO-UK"), ClassificationLevel::Secret)
            .with_category(mim_labeling::CategoryMarking::handling_caveat("LOCSEN"));
        tests.push(AdatpTestResult {
            id: "spif-uk-secret-valid".into(),
            suite: "XML-SPIF".into(),
            passed: validator.validate_label(&uk_secret).is_ok(),
            message: "UK DEMO SECRET + LOCSEN passes SPIF validation".into(),
        });
        Self::finalize_suite("XML-SPIF Policy Ingestion", tests)
    }

    fn finalize_suite(name: &str, tests: Vec<AdatpTestResult>) -> AdatpSuiteResult {
        let passed = tests.iter().filter(|t| t.passed).count();
        let failed = tests.len().saturating_sub(passed);
        AdatpSuiteResult {
            name: name.to_owned(),
            passed,
            failed,
            total: tests.len(),
            tests,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn adatp_suite_is_fully_compliant() {
        let report = AdatpConformanceRunner::new().evaluate();
        assert!(
            report.is_fully_compliant,
            "failures: {:?}",
            report.recommendations
        );
    }
}
