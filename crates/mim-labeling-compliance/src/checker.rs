use mim_audit::{AuditEventKind, AuditLog, AuditRecord};
use mim_crypto::{conformance_key_ring, NmbKeyRing, selected_provider};
use mim_dcs::{CrossDomainGuard, CrossDomainTransfer, GuardDecision};
use mim_labeling::{
    CategoryMarking, ClassificationLevel, ConfidentialityLabel, LabelPolicy,
};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use mim_stanag4778::{AssertionBinding, BindingDataObject, RestEnvelope, SmtpHeaderBinding};
use mim_ztdf::ZtdfPackage;

use crate::report::{
    LabelingComplianceReport, LabelingComplianceStatus, LabelingDimension,
    LabelingDimensionResult,
};
use crate::requirements::LabelingComplianceRequirements;

/// Evaluates labeling stack compliance against STANAG 4774/4778, ZTDF, DCS, SPIF, and audit.
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
            self.dimension_policy_plane(),
            self.dimension_nato_policy(),
            self.dimension_capco_policy(),
            self.dimension_uk_policy(),
            self.dimension_spif(),
            self.dimension_assertion_binding(),
            self.dimension_audit_trail(),
            self.dimension_fips_crypto(),
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

    fn keys() -> mim_crypto::NmbKeyRing {
        conformance_key_ring().expect("conformance key ring")
    }

    fn dimension_stanag4774(&self) -> LabelingDimensionResult {
        let label = Self::sample_label();
        let codec = Stanag4774Codec::new();
        let xml_ok = codec.round_trip(&label, Stanag4774Format::Xml).is_ok();
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
        let ring = Self::keys();
        let keys = &ring.nmb;
        let label = Self::sample_label();
        let payload = br#"{"instances":[]}"#;
        let profiles = [
            BindingDataObject::embedded(label.clone(), payload).is_ok(),
            BindingDataObject::xml_embedded(label.clone(), payload).is_ok(),
            BindingDataObject::encapsulated(label.clone(), payload).is_ok(),
            BindingDataObject::detached(label.clone(), payload, "label.xml").is_ok(),
            BindingDataObject::assertion_bound(label, payload, keys.signing_key())
                .and_then(|b| b.verify(payload, Some(keys.verifying_key())))
                .is_ok(),
            RestEnvelope::wrap(&Self::sample_label(), payload, keys.signing_key())
                .and_then(|e| e.verify(keys.verifying_key()))
                .is_ok(),
            SmtpHeaderBinding::create(&Self::sample_label(), payload, keys.signing_key())
                .and_then(|b| b.verify(payload, keys.verifying_key()))
                .is_ok(),
        ];
        let passed = profiles.iter().filter(|ok| **ok).count();
        let score = passed as f64 / profiles.len() as f64;
        LabelingDimensionResult {
            dimension: LabelingDimension::Stanag4778,
            status: status_from_score(score, self.requirements.require_stanag4778),
            score,
            message: if score >= 1.0 {
                "All STANAG 4778 binding profiles operational with integrity verification".into()
            } else {
                "STANAG 4778 binding profile coverage incomplete".into()
            },
        }
    }

    fn dimension_ztdf(&self) -> LabelingDimensionResult {
        let ring = Self::keys();
        let label = Self::sample_label();
        let payload = br#"{"modelVersion":"5.1.0"}"#.to_vec();
        let ok = ZtdfPackage::create(
            &label,
            payload,
            ring.nmb_signing(),
            ring.nmb_verifying(),
            ring.kas_verifying(),
        )
        .and_then(|pkg| pkg.verify(ring.nmb_verifying(), ring.kas_signing()))
        .is_ok();
        let score = if ok { 1.0 } else { 0.0 };
        LabelingDimensionResult {
            dimension: LabelingDimension::Ztdf,
            status: status_from_score(score, self.requirements.require_ztdf),
            score,
            message: if ok {
                "ZTDF AES-256-GCM package with NMBS assertion verified".into()
            } else {
                "ZTDF packaging failed".into()
            },
        }
    }

    fn dimension_dcs(&self) -> LabelingDimensionResult {
        let ring = Self::keys();
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = Self::sample_label();
        let inbound = BindingDataObject::assertion_bound(
            label.clone(),
            br#"{"instances":[]}"#,
            ring.nmb_signing(),
        )
        .expect("inbound binding");
        let transfer = CrossDomainTransfer {
            source_domain: guard.source().id.clone(),
            target_domain: guard.target().id.clone(),
            label: label.clone(),
            payload: r#"{"instances":[]}"#.to_owned(),
            inbound_binding: inbound,
            nmb_signing_key: ring.nmb_signing().clone(),
            nmb_verifying_key: ring.nmb_verifying().clone(),
            kas_signing_key: ring.kas_signing().clone(),
            kas_verifying_key: ring.kas_verifying().clone(),
        };
        let audit = AuditLog::memory().with_signing_key(ring.nmb_signing().clone());
        let allow_ok = transfer
            .execute(&guard, &audit)
            .map(|o| matches!(o, mim_dcs::TransferOutcome::Released { .. }))
            .unwrap_or(false);
        let audit_ok = audit.len() >= 2 && audit.verify_chain().is_ok();
        let deny_label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["DEU".into()]));
        let deny_ok = guard
            .evaluate(&deny_label)
            .map(|r| r.decision == GuardDecision::Deny)
            .unwrap_or(false);
        let score = if allow_ok && deny_ok && audit_ok {
            1.0
        } else if allow_ok && deny_ok {
            0.75
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
                "DCS guard with mandatory NMBS binding and audit verified".into()
            } else if allow_ok && deny_ok {
                "DCS transfer succeeded but audit trail incomplete".into()
            } else {
                "DCS cross-domain evaluation incomplete".into()
            },
        }
    }

    fn dimension_policy_plane(&self) -> LabelingDimensionResult {
        use mim_labeling::SecurityDomain;
        use mim_policy::{
            AccessOperation, PolicyAdministrationPoint, PolicyEnforcementPoint,
            PolicyInformationPoint, SubjectAttributes,
        };

        let pap = PolicyAdministrationPoint::with_preset_high_to_low();
        let pap_ok = !pap.store().cross_domain_policies().is_empty();
        let pep = PolicyEnforcementPoint::new(
            PolicyInformationPoint::new(),
            mim_policy::PolicyDecisionPoint::new(pap.into_store()),
        );
        let source = SecurityDomain::new("DOMAIN-HIGH", "High Side", ClassificationLevel::Secret)
            .with_releasable_to(vec!["USA".into(), "GBR".into(), "DEU".into()]);
        let target = SecurityDomain::new("DOMAIN-LOW", "Low Side", ClassificationLevel::Restricted)
            .with_releasable_to(vec!["USA".into(), "GBR".into()]);
        let label = Self::sample_label();
        let pip_ok = PolicyInformationPoint::new()
            .access_context(
                SubjectAttributes::new("operator", ClassificationLevel::Secret),
                &label,
                AccessOperation::Read,
                &source,
            )
            .is_ok();
        let pdp_ok = pep
            .evaluate_cross_domain(
                SubjectAttributes::new("guard", ClassificationLevel::Secret),
                &label,
                &source,
                &target,
            )
            .map(|decision| decision.effect != mim_policy::PolicyEffect::Deny)
            .unwrap_or(false);
        let caveat_label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Restricted)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]))
            .with_category(CategoryMarking::handling_caveat("LOCSEN"));
        let caveat_denied = pep
            .evaluate_cross_domain(
                SubjectAttributes::new("guard", ClassificationLevel::Secret),
                &caveat_label,
                &source,
                &target,
            )
            .map(|decision| decision.effect == mim_policy::PolicyEffect::Deny)
            .unwrap_or(false);
        let caveat_permitted = pep
            .evaluate_cross_domain(
                SubjectAttributes::new("guard", ClassificationLevel::Secret)
                    .with_handling_caveat("LOCSEN"),
                &caveat_label,
                &source,
                &target,
            )
            .map(|decision| decision.effect == mim_policy::PolicyEffect::Permit)
            .unwrap_or(false);
        let pep_ok = pep
            .enforce_access(
                SubjectAttributes::new("operator", ClassificationLevel::Secret),
                &label,
                AccessOperation::Read,
                &source,
            )
            .is_ok();
        let policy_checks = [pip_ok, pdp_ok, pep_ok, pap_ok, caveat_denied, caveat_permitted];
        let score = policy_checks
            .iter()
            .filter(|ok| **ok)
            .count() as f64
            / policy_checks.len() as f64;
        LabelingDimensionResult {
            dimension: LabelingDimension::PolicyPlane,
            status: status_from_score(score, self.requirements.require_policy_plane),
            score,
            message: if score >= 1.0 {
                "PIP, PAP/PRP, PDP, and PEP policy plane operational".into()
            } else {
                "Policy plane components incomplete".into()
            },
        }
    }

    fn dimension_nato_policy(&self) -> LabelingDimensionResult {
        let policy = LabelPolicy::nato();
        let ok = policy.allows_classification(ClassificationLevel::Secret)
            && mim_spif::SpifValidator::with_defaults()
                .validate_label(&Self::sample_label())
                .is_ok();
        let score = if ok { 1.0 } else { 0.0 };
        LabelingDimensionResult {
            dimension: LabelingDimension::NatoPolicy,
            status: status_from_score(score, self.requirements.require_nato_policy),
            score,
            message: if ok {
                "NATO SPIF policy profile loaded and validates labels".into()
            } else {
                "NATO policy validation failed".into()
            },
        }
    }

    fn dimension_capco_policy(&self) -> LabelingDimensionResult {
        let label = ConfidentialityLabel::new(LabelPolicy::new("US"), ClassificationLevel::Secret);
        let ok = mim_spif::SpifValidator::with_defaults()
            .validate_label(&label)
            .is_ok();
        LabelingDimensionResult {
            dimension: LabelingDimension::CapcoPolicy,
            status: status_from_score(if ok { 1.0 } else { 0.0 }, self.requirements.require_capco_policy),
            score: if ok { 1.0 } else { 0.0 },
            message: if ok {
                "US CAPCO SPIF policy validates labels".into()
            } else {
                "CAPCO policy validation failed".into()
            },
        }
    }

    fn dimension_uk_policy(&self) -> LabelingDimensionResult {
        let label = ConfidentialityLabel::new(LabelPolicy::new("DEMO-UK"), ClassificationLevel::Secret)
            .with_category(CategoryMarking::handling_caveat("LOCSEN"));
        let ok = mim_spif::SpifValidator::with_defaults()
            .validate_label(&label)
            .is_ok();
        LabelingDimensionResult {
            dimension: LabelingDimension::UkPolicy,
            status: status_from_score(if ok { 1.0 } else { 0.0 }, self.requirements.require_uk_policy),
            score: if ok { 1.0 } else { 0.0 },
            message: if ok {
                "UK DEMO SPIF policy validates labels".into()
            } else {
                "UK policy validation failed".into()
            },
        }
    }

    fn dimension_spif(&self) -> LabelingDimensionResult {
        let registry = mim_spif::SpifRegistry::with_defaults();
        let ok = registry.get("NATO").is_some()
            && registry.get("US").is_some()
            && registry.get("DEMO-UK").is_some()
            && registry.get("ACME").is_some();
        LabelingDimensionResult {
            dimension: LabelingDimension::SpifIngestion,
            status: status_from_score(if ok { 1.0 } else { 0.0 }, self.requirements.require_spif),
            score: if ok { 1.0 } else { 0.0 },
            message: if ok {
                "XML-SPIF policy ingestion operational".into()
            } else {
                "SPIF ingestion failed".into()
            },
        }
    }

    fn dimension_assertion_binding(&self) -> LabelingDimensionResult {
        let ring = Self::keys();
        let label = Self::sample_label();
        let payload = br#"{"test":true}"#;
        let ok = AssertionBinding::create(&label, payload, ring.nmb_signing())
            .and_then(|b| b.verify(payload, ring.nmb_verifying()))
            .is_ok();
        LabelingDimensionResult {
            dimension: LabelingDimension::AssertionBinding,
            status: status_from_score(if ok { 1.0 } else { 0.0 }, self.requirements.require_assertion_binding),
            score: if ok { 1.0 } else { 0.0 },
            message: if ok {
                "STANAG 4778 NMBS RSA-PSS-SHA256 assertion binding verified".into()
            } else {
                "Assertion binding verification failed".into()
            },
        }
    }

    fn dimension_audit_trail(&self) -> LabelingDimensionResult {
        let ring = Self::keys();
        let audit = AuditLog::memory().with_signing_key(ring.nmb_signing().clone());
        let record = AuditRecord::new(
            AuditEventKind::CrossDomainEvaluate,
            "checker",
            Self::sample_label(),
            "audit-test",
            "evaluate",
            "audit trail smoke test",
        );
        let ok = audit.record(record.clone()).is_ok()
            && audit.len() == 1
            && audit.envelopes().len() == 1
            && audit.verify_chain().is_ok()
            && audit.export_siem().is_ok();
        let file_path = std::env::temp_dir().join(format!(
            "labeling-audit-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let file_audit = AuditLog::file(&file_path)
            .expect("file audit")
            .with_signing_key(ring.nmb_signing().clone());
        let file_ok = file_audit.record(record).is_ok()
            && file_audit.len() == 1
            && AuditLog::load_from_file(&file_path)
                .expect("reload")
                .verify_chain()
                .is_ok();
        let _ = std::fs::remove_file(file_path);
        let ok = ok && file_ok;
        LabelingDimensionResult {
            dimension: LabelingDimension::AuditTrail,
            status: status_from_score(if ok { 1.0 } else { 0.0 }, self.requirements.require_audit),
            score: if ok { 1.0 } else { 0.0 },
            message: if ok {
                "Immutable audit trail records guard decisions".into()
            } else {
                "Audit trail not operational".into()
            },
        }
    }

    fn dimension_fips_crypto(&self) -> LabelingDimensionResult {
        let provider = selected_provider();
        let name = provider.name();
        let (score, detail) = if name.contains("FIPS 140-3 validated") {
            (1.0, "FIPS 140-3 validated AWS-LC module active")
        } else if name.contains("FIPS") {
            (1.0, "FIPS-capable AWS-LC module active")
        } else if name.contains("ring") {
            (
                0.5,
                "non-FIPS ring backend — rebuild with default `mim-crypto` features for FIPS 140-3",
            )
        } else {
            (0.0, "unknown crypto provider")
        };
        LabelingDimensionResult {
            dimension: LabelingDimension::FipsCrypto,
            status: status_from_score(score, self.requirements.require_fips_crypto),
            score,
            message: format!("Crypto provider: {name}. {detail}"),
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
                "Labeling stack meets all STANAG 4774/4778, ZTDF, DCS, SPIF, and audit requirements.".into(),
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
        assert_eq!(report.dimensions.len(), 12);
    }
}
