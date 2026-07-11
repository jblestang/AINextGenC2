//! Cross-domain DCS scenario: labeled MIM radar exchange across security domains.

use mim_audit::AuditLog;
use mim_crypto::conformance_keypair;
use mim_dcs::{
    CrossDomainGuard, CrossDomainTransfer, GuardDecision, LabeledMimExchange, TransferOutcome,
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
}

/// DCS cross-domain scenario wrapping the air defense radar exchange.
#[derive(Clone, Debug)]
pub struct DcsCrossDomainScenario {
    guard: CrossDomainGuard,
    label: ConfidentialityLabel,
}

impl Default for DcsCrossDomainScenario {
    fn default() -> Self {
        Self {
            guard: CrossDomainGuard::preset_high_to_low(),
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

    pub fn run(&self, stack: &MimStack) -> mim_core::MimResult<DcsScenarioOutput> {
        let keys = conformance_keypair().map_err(|e| mim_core::MimError::Validation(e.to_string()))?;
        let registry = stack.registry();
        let radar_store = AirDefenseRadarScenario::demo().build_store(registry)?;

        let serializer = Serializer::new(registry.clone());
        let labeled = LabeledMimExchange::build(
            &radar_store,
            &serializer,
            &self.label,
            keys.signing_key(),
            keys.verifying_key(),
            keys.verifying_key(),
            true,
        )?;

        let inbound_binding = BindingDataObject::assertion_bound(
            self.label.clone(),
            labeled.mim_json.as_bytes(),
            keys.signing_key(),
        )?;

        let transfer = CrossDomainTransfer {
            source_domain: self.guard.source().id.clone(),
            target_domain: self.guard.target().id.clone(),
            label: self.label.clone(),
            payload: labeled.mim_json.clone(),
            inbound_binding,
            nmb_signing_key: keys.signing_key().clone(),
            nmb_verifying_key: keys.verifying_key().clone(),
            kas_signing_key: keys.signing_key().clone(),
            kas_verifying_key: keys.verifying_key().clone(),
        };

        let audit = AuditLog::memory();
        let guard_result = transfer.guard_result(&self.guard)?;
        let outcome = transfer.execute(&self.guard, &audit)?;

        let (label_xml, ztdf_manifest) = match &outcome {
            TransferOutcome::Released {
                label_xml,
                ztdf_manifest,
                ..
            } => (Some(label_xml.clone()), ztdf_manifest.clone()),
            TransferOutcome::Denied { .. } => (None, None),
        };

        let labeling_report = LabelingComplianceChecker::with_defaults().evaluate();

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
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn dcs_scenario_downgrades_and_releases() {
        let stack = MimStack::load().expect("stack");
        let output = DcsCrossDomainScenario::demo().run(&stack).expect("run");
        assert_eq!(output.transfer_decision, "DOWNGRADE");
        assert!(output.labeling_compliant);
        assert!(output.label_xml.is_some());
        assert!(output.ztdf_manifest.is_some());
    }
}
