//! Cross-domain DCS scenario: labeled MIM radar exchange across security domains.

use mim_audit::{forward_siem_to_file, AuditLog};
use mim_crypto::{load_key_ring_for, PkiMode};
use mim_dcs::{
    bundled_config_path, CrossDomainGuard, CrossDomainTransfer, DcsConfig, GuardDecision,
    LabeledMimExchange, TransferOutcome,
};
use mim_labeling::{
    CategoryMarking, ClassificationLevel, ConfidentialityLabel, LabelPolicy,
};
use mim_labeling_compliance::LabelingComplianceChecker;
use mim_runtime::Serializer;
use mim_stanag4778::BindingDataObject;
use serde::{Deserialize, Serialize};

use crate::scenarios::air_defense_radar::AirDefenseRadarScenario;
use crate::MimStack;

/// Output of the DCS cross-domain labeling scenario.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DcsScenarioOutput {
    pub source_label: String,
    pub transfer_decision: String,
    pub transfer_reason: String,
    pub label_xml: Option<String>,
    pub ztdf_manifest: Option<String>,
    pub labeling_compliant: bool,
    pub mim_json: String,
    pub audit_record_count: usize,
    pub audit_chain_verified: bool,
    pub siem_export_path: Option<String>,
    pub accredited_profile: bool,
    pub worm_audit_verified: bool,
}

/// DCS cross-domain scenario wrapping the air defense radar exchange.
#[derive(Clone, Debug)]
pub struct DcsCrossDomainScenario {
    guard: CrossDomainGuard,
    label: ConfidentialityLabel,
}

impl Default for DcsCrossDomainScenario {
    fn default() -> Self {
        let config = DcsConfig::load_path(bundled_config_path("dcs-coalition.toml"))
            .unwrap_or_else(|_| DcsConfig::conformance_high_to_low());
        Self {
            guard: CrossDomainGuard::from_config(&config)
                .unwrap_or_else(|_| CrossDomainGuard::preset_high_to_low()),
            label: ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
                .with_category(CategoryMarking::releasable_to(vec![
                    "USA".into(),
                    "GBR".into(),
                ])),
        }
    }
}

impl DcsCrossDomainScenario {
    pub fn demo() -> Self {
        Self::default()
    }

    fn config(&self) -> DcsConfig {
        DcsConfig::load_path(bundled_config_path("dcs-coalition.toml"))
            .unwrap_or_else(|_| DcsConfig::conformance_high_to_low())
    }

    pub fn run(&self, stack: &MimStack) -> mim_core::MimResult<DcsScenarioOutput> {
        self.run_with_pki(stack, PkiMode::Production)
    }

    /// Lab run using bundled conformance keys (no environment variables).
    pub fn run_lab(&self, stack: &MimStack) -> mim_core::MimResult<DcsScenarioOutput> {
        self.run_with_pki(stack, PkiMode::Lab)
    }

    /// Accredited guard run — WORM audit, production PKI only, fail-closed audit/SIEM.
    pub fn run_accredited(&self, stack: &MimStack) -> mim_core::MimResult<DcsScenarioOutput> {
        let config = DcsConfig::load_path(bundled_config_path("dcs-accredited.toml"))
            .map_err(|e| mim_core::MimError::Validation(e))?;
        config
            .validate_accredited_profile()
            .map_err(mim_core::MimError::Validation)?;
        self.run_with_config(stack, &config, PkiMode::Production)
    }

    fn run_with_pki(&self, stack: &MimStack, mode: PkiMode) -> mim_core::MimResult<DcsScenarioOutput> {
        let config = self.config();
        self.run_with_config(stack, &config, mode)
    }

    fn run_with_config(
        &self,
        stack: &MimStack,
        config: &DcsConfig,
        mode: PkiMode,
    ) -> mim_core::MimResult<DcsScenarioOutput> {
        if config.is_accredited_profile() && mode == PkiMode::Lab {
            return Err(mim_core::MimError::Validation(
                "accredited guard rejects lab/conformance PKI".into(),
            ));
        }
        config
            .validate_accredited_profile()
            .map_err(mim_core::MimError::Validation)?;
        let ring = load_key_ring_for(mode).map_err(|e| mim_core::MimError::Validation(e.to_string()))?;
        let registry = stack.registry();
        let radar_store = AirDefenseRadarScenario::demo().build_store(registry)?;

        let serializer = Serializer::new(registry.clone());
        let labeled = LabeledMimExchange::build(
            &radar_store,
            &serializer,
            &self.label,
            ring.nmb_signing(),
            ring.nmb_verifying(),
            ring.kas_verifying(),
            true,
        )?;

        let inbound_binding = BindingDataObject::assertion_bound(
            self.label.clone(),
            labeled.mim_json.as_bytes(),
            ring.nmb_signing(),
        )?;

        let transfer = CrossDomainTransfer {
            source_domain: self.guard.source().id.clone(),
            target_domain: self.guard.target().id.clone(),
            label: self.label.clone(),
            payload: labeled.mim_json.clone(),
            inbound_binding,
            nmb_signing_key: ring.nmb_signing().clone(),
            nmb_verifying_key: ring.nmb_verifying().clone(),
            kas_signing_key: ring.kas_signing().clone(),
            kas_verifying_key: ring.kas_verifying().clone(),
        };

        let audit = config
            .build_audit_log()
            .map_err(|e| mim_core::MimError::Validation(e))?
            .unwrap_or_else(|| AuditLog::memory())
            .with_signing_key(ring.nmb_signing().clone());
        let guard = CrossDomainGuard::from_config(config)
            .map_err(|e| mim_core::MimError::Validation(e.to_string()))?
            .with_audit(audit.clone());

        let guard_result = transfer.guard_result(&guard)?;
        let outcome = transfer.execute(&guard, &audit)?;

        let (label_xml, ztdf_manifest) = match &outcome {
            TransferOutcome::Released {
                label_xml,
                ztdf_manifest,
                ..
            } => (Some(label_xml.clone()), ztdf_manifest.clone()),
            TransferOutcome::Denied { .. } => (None, None),
        };

        let labeling_report = LabelingComplianceChecker::with_defaults().evaluate();
        let audit_chain_verified = audit.verify_chain().is_ok();
        let accredited_profile = config.is_accredited_profile();
        if accredited_profile && !audit_chain_verified {
            return Err(mim_core::MimError::Validation(
                "accredited guard requires verifiable signed audit chain".into(),
            ));
        }
        let worm_audit_verified = if config.audit.sink_type == mim_dcs::AuditSinkType::Worm {
            audit
                .envelopes()
                .last()
                .is_some_and(|_| audit.verify_chain().is_ok())
        } else {
            false
        };
        let siem_export_path = config.resolved_siem_export_path().map(|resolved| {
            let _ = forward_siem_to_file(&audit, &resolved);
            resolved.display().to_string()
        });
        if let Err(err) = config.forward_audit_siem(&audit) {
            if accredited_profile {
                return Err(mim_core::MimError::Validation(err));
            }
        }

        Ok(DcsScenarioOutput {
            source_label: format!(
                "{} / REL {}",
                self.label.classification.as_stanag_str(),
                self.label.releasable_countries().join(",")
            ),
            transfer_decision: match guard_result.decision {
                GuardDecision::Allow => "ALLOW".to_owned(),
                GuardDecision::Deny => "DENY".to_owned(),
                GuardDecision::Downgrade => "DOWNGRADE".to_owned(),
            },
            transfer_reason: guard_result.reason,
            label_xml,
            ztdf_manifest,
            labeling_compliant: labeling_report.is_fully_compliant,
            mim_json: labeled.mim_json,
            audit_record_count: audit.len(),
            audit_chain_verified,
            siem_export_path,
            accredited_profile,
            worm_audit_verified,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use mim_dcs::AuditSinkType;

    #[test]
    fn dcs_scenario_downgrades_and_releases() {
        let stack = MimStack::load().expect("stack");
        let output = DcsCrossDomainScenario::demo().run_lab(&stack).expect("run");
        assert_eq!(output.transfer_decision, "DOWNGRADE");
        assert!(output.labeling_compliant);
        assert!(output.label_xml.is_some());
        assert!(output.ztdf_manifest.is_some());
        assert!(output.audit_record_count >= 2);
        assert!(output.audit_chain_verified);
        assert!(!output.accredited_profile);
    }

    #[test]
    fn accredited_profile_rejects_lab_pki() {
        let stack = MimStack::load().expect("stack");
        let config = DcsConfig::load_path(bundled_config_path("dcs-accredited.toml")).expect("load");
        let scenario = DcsCrossDomainScenario::demo();
        let err = scenario
            .run_with_config(&stack, &config, PkiMode::Lab)
            .expect_err("lab pki");
        assert!(err.to_string().contains("accredited guard rejects"));
    }

    #[test]
    fn accredited_config_requires_worm_sink() {
        let path = bundled_config_path("dcs-accredited.toml");
        let config = DcsConfig::load_path(&path).expect("load");
        assert!(config.is_accredited_profile());
        assert_eq!(config.audit.sink_type, AuditSinkType::Worm);
        config.validate_accredited_profile().expect("valid");
        let guard = config.build_guard().expect("guard");
        assert!(guard.is_accredited());
    }

    #[test]
    fn non_worm_sink_rejected_for_accredited() {
        let mut config = DcsConfig::conformance_high_to_low();
        config.accredited = true;
        config.audit.path = Some("target/test-audit.jsonl".into());
        config.audit.sink_type = AuditSinkType::File;
        let err = config.validate_accredited_profile().expect_err("worm required");
        assert!(err.contains("worm"));
    }
}
