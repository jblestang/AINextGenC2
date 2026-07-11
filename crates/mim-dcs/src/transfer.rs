use mim_labeling::{ConfidentialityLabel, DomainId, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use mim_stanag4778::BindingDataObject;
use mim_ztdf::ZtdfPackage;
use serde::{Deserialize, Serialize};

use crate::guard::{validate_domain_pair, CrossDomainGuard, GuardDecision, GuardResult};

/// Outcome of a cross-domain transfer through the DCS guard.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferOutcome {
    Released {
        label_xml: String,
        payload: String,
        ztdf_manifest: Option<String>,
    },
    Denied {
        reason: String,
    },
}

/// Cross-domain transfer request for labeled MIM data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossDomainTransfer {
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub label: ConfidentialityLabel,
    pub payload: String,
    pub binding_secret: Vec<u8>,
}

impl CrossDomainTransfer {
    pub fn execute(&self, guard: &CrossDomainGuard) -> LabelResult<TransferOutcome> {
        validate_domain_pair(&self.source_domain, &self.target_domain)?;
        let result = guard.evaluate(&self.label)?;

        match result.decision {
            GuardDecision::Allow | GuardDecision::Downgrade => {
                let effective = result
                    .effective_label
                    .ok_or_else(|| {
                        mim_labeling::LabelError::CrossDomain(
                            "guard approved transfer but no effective label".into(),
                        )
                    })?;

                let codec = Stanag4774Codec::new();
                let label_xml = codec.serialize(&effective, Stanag4774Format::Xml)?;

                let bdo = BindingDataObject::assertion_bound(
                    effective.clone(),
                    self.payload.as_bytes(),
                    &self.binding_secret,
                )?;
                bdo.verify(self.payload.as_bytes(), Some(&self.binding_secret))?;

                let ztdf = ZtdfPackage::create(
                    &effective,
                    self.payload.as_bytes().to_vec(),
                    &self.binding_secret,
                )?;
                ztdf.verify(&self.binding_secret)?;

                Ok(TransferOutcome::Released {
                    label_xml,
                    payload: self.payload.clone(),
                    ztdf_manifest: Some(ztdf.manifest_json()?),
                })
            }
            GuardDecision::Deny => Ok(TransferOutcome::Denied {
                reason: result.reason,
            }),
        }
    }

    pub fn guard_result(&self, guard: &CrossDomainGuard) -> LabelResult<GuardResult> {
        guard.evaluate(&self.label)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{CategoryMarking, ClassificationLevel, LabelPolicy};

    use super::*;

    const SECRET: &[u8] = b"compliance-test-binding-secret!!";

    #[test]
    fn transfer_downgrades_secret_payload() {
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into(), "GBR".into()]));
        let transfer = CrossDomainTransfer {
            source_domain: guard.source().id.clone(),
            target_domain: guard.target().id.clone(),
            label,
            payload: r#"{"instances":[]}"#.to_owned(),
            binding_secret: SECRET.to_vec(),
        };
        let outcome = transfer.execute(&guard).expect("execute");
        assert!(matches!(outcome, TransferOutcome::Released { .. }));
    }
}
