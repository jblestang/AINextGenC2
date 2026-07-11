use mim_dcs::{CrossDomainGuard, CrossDomainTransfer, GuardDecision};
use mim_labeling::{
    CategoryMarking, ClassificationLevel, ConfidentialityLabel, LabelPolicy,
};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use mim_stanag4778::{AssertionBinding, BindingDataObject};
use mim_ztdf::ZtdfPackage;

use crate::report::{
    LabelingComplianceReport, LabelingComplianceStatus, LabelingDimension,
    LabelingDimensionResult,
};
use crate::requirements::LabelingComplianceRequirements;

const BINDING_SECRET: &[u8] = b"compliance-test-binding-secret!!";

/// Evaluates labeling stack compliance against STANAG 4774/4778, ZTDF, and DCS.
#[derive(Clone, Debug)]
pub struct LabelingComplianceChecker {
    requirements: LabelingComplianceRequirements,
}

impl LabelingComplianceChecker {
    pub fn new(requirements: LabelingComplianceRequirements) -> Self {
        Self { requirements }
    }

    pub fn with_defaults() -> Self {
        Self::new(LabelingComplianceRequirements::default())
    }

    pub fn evaluate(&self) -> LabelingComplianceReport {
        let dimensions = vec![
            self.dimension_stanag4774(),
            self.dimension_stanag4778(),
            self.dimension_ztdf(),
            self.dimension_dcs(),
            self.dimension_nato_policy(),
            self.dimension_assertion_binding(),
        ];

        let overall_score =
            dimensions.iter().map(|d| d.score).sum::<f64>() / dimensions.len() as f64;

        let is_fully_compliant = dimensions
            .iter()
            .all(|d| d.status == LabelingComplianceStatus::Compliant);

        let recommendations = self.recommendations(&dimensions);

        LabelingComplianceReport {
            overall_score,
            is_fully_compliant,
            dimensions,
            recommendations,
        }
    }

    fn sample_label() -> ConfidentialityLabel {
        ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec![
                "USA".into(),
                "GBR".into(),
            ]))
    }

    fn dimension_stanag4774(&self) -> LabelingDimensionResult {
        let label = Self::sample_label();
        let codec = Stanag4774Codec::new();
        let xml_ok = codec
            .round_trip(&label, Stanag4774Format::Xml)
            .is_ok();
        let json_ok = codec
            .round_trip(&label, Stanag4774Format::JsonStructured)
            .is_ok();
        let score = if xml_ok && json_ok { 1.0 } else if xml_ok || json_ok { 0.5 } else { 0.0 };
        LabelingDimensionResult {
            dimension: LabelingDimension::Stanag4774,
            status: status_from_score(score, self.requirements.require_stanag4774),
            score,
            message: if xml_ok && json_ok {
                "STANAG 4774 XML and JSON-structured round-trip passed".into()
            } else {
                "STANAG 4774 codec round-trip failed".into()
            },
        }
    }

    fn dimension_stanag4778(&self) -> LabelingDimensionResult {
        let label = Self::sample_label();
        let payload = br#"{"instances":[]}"#;
        let bdo_ok = BindingDataObject::assertion_bound(label.clone(), payload, BINDING_SECRET)
            .and_then(|bdo| bdo.verify(payload, Some(BINDING_SECRET)))
            .is_ok();
        let embedded_ok =
            BindingDataObject::embedded(label, payload).is_ok();
        let score = if bdo_ok && embedded_ok { 1.0 } else if bdo_ok || embedded_ok { 0.5 } else { 0.0 };
        LabelingDimensionResult {
            dimension: LabelingDimension::Stanag4778,
            status: status_from_score(score, self.requirements.require_stanag4778),
            score,
            message: if bdo_ok {
                "STANAG 4778 assertion and embedded binding profiles operational".into()
            } else {
                "STANAG 4778 binding failed".into()
            },
        }
    }

    fn dimension_ztdf(&self) -> LabelingDimensionResult {
        let label = Self::sample_label();
        let payload = br#"{"modelVersion":"5.1.0"}"#.to_vec();
        let ok = ZtdfPackage::create(&label, payload, BINDING_SECRET)
            .and_then(|pkg| pkg.verify(BINDING_SECRET))
            .is_ok();
        let score = if ok { 1.0 } else { 0.0 };
        LabelingDimensionResult {
            dimension: LabelingDimension::Ztdf,
            status: status_from_score(score, self.requirements.require_ztdf),
            score,
            message: if ok {
                "ZTDF manifest with STANAG 4774 assertion and binding verified".into()
            } else {
                "ZTDF packaging failed".into()
            },
        }
    }

    fn dimension_dcs(&self) -> LabelingDimensionResult {
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = Self::sample_label();
        let transfer = CrossDomainTransfer {
            source_domain: guard.source().id.clone(),
            target_domain: guard.target().id.clone(),
            label: label.clone(),
            payload: r#"{"instances":[]}"#.to_owned(),
            binding_secret: BINDING_SECRET.to_vec(),
        };
        let downgrade_label =
            ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Restricted)
                .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let deny_label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["DEU".into()]));
        let allow_ok = transfer
            .execute(&guard)
            .map(|o| matches!(o, mim_dcs::TransferOutcome::Released { .. }))
            .unwrap_or(false);
        let deny_ok = guard
            .evaluate(&deny_label)
            .map(|r| r.decision == GuardDecision::Deny)
            .unwrap_or(false);
        let downgrade_ok = guard
            .evaluate(&downgrade_label)
            .map(|r| r.decision == GuardDecision::Allow)
            .unwrap_or(false);
        let score = if allow_ok && deny_ok && downgrade_ok {
            1.0
        } else if allow_ok || deny_ok {
            0.5
        } else {
            0.0
        };
        LabelingDimensionResult {
            dimension: LabelingDimension::DcsCrossDomain,
            status: status_from_score(score, self.requirements.require_dcs),
            score,
            message: if score >= 1.0 {
                "DCS cross-domain guard allow/deny/downgrade policies verified".into()
            } else {
                "DCS cross-domain evaluation incomplete".into()
            },
        }
    }

    fn dimension_nato_policy(&self) -> LabelingDimensionResult {
        let policy = LabelPolicy::nato();
        let ok = policy.allows_classification(ClassificationLevel::Secret)
            && policy.allows_classification(ClassificationLevel::Unclassified)
            && !LabelPolicy::public_day_zero().allows_classification(ClassificationLevel::Secret);
        let score = if ok { 1.0 } else { 0.0 };
        LabelingDimensionResult {
            dimension: LabelingDimension::NatoPolicy,
            status: status_from_score(score, self.requirements.require_nato_policy),
            score,
            message: if ok {
                "NATO and PUBLIC SPIF policy profiles loaded".into()
            } else {
                "NATO policy validation failed".into()
            },
        }
    }

    fn dimension_assertion_binding(&self) -> LabelingDimensionResult {
        let label = Self::sample_label();
        let payload = br#"{"test":true}"#;
        let ok = AssertionBinding::create(&label, payload, BINDING_SECRET)
            .and_then(|b| b.verify(payload, BINDING_SECRET))
            .is_ok();
        let score = if ok { 1.0 } else { 0.0 };
        LabelingDimensionResult {
            dimension: LabelingDimension::AssertionBinding,
            status: status_from_score(score, self.requirements.require_assertion_binding),
            score,
            message: if ok {
                "STANAG 4778 HMAC-SHA256 assertion binding verified".into()
            } else {
                "Assertion binding verification failed".into()
            },
        }
    }

    fn recommendations(&self, dimensions: &[LabelingDimensionResult]) -> Vec<String> {
        let mut items = Vec::new();
        for dimension in dimensions {
            if dimension.status != LabelingComplianceStatus::Compliant {
                items.push(format!(
                    "Improve {:?}: {}",
                    dimension.dimension, dimension.message
                ));
            }
        }
        if items.is_empty() {
            items.push(
                "Labeling stack meets all STANAG 4774/4778, ZTDF, and DCS requirements.".into(),
            );
        }
        items
    }
}

fn status_from_score(score: f64, required: bool) -> LabelingComplianceStatus {
    if !required {
        return LabelingComplianceStatus::Compliant;
    }
    if score >= 1.0 {
        LabelingComplianceStatus::Compliant
    } else if score > 0.0 {
        LabelingComplianceStatus::Partial
    } else {
        LabelingComplianceStatus::NonCompliant
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn labeling_stack_is_fully_compliant() {
        let checker = LabelingComplianceChecker::with_defaults();
        let report = checker.evaluate();
        assert!(report.is_fully_compliant, "{report:?}");
        assert_eq!(report.dimensions.len(), 6);
    }
}
