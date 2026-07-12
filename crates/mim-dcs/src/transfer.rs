use mim_audit::{AuditEventKind, AuditLog, AuditRecord};
use mim_crypto::{sha256_base64, SigningKey, VerifyingKey};
use mim_labeling::{ConfidentialityLabel, DomainId, LabelError, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use mim_stanag4778::{BindingDataObject, BindingMethod};
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
        ztdf_package_zip: Option<Vec<u8>>,
    },
    Denied {
        reason: String,
    },
}

/// Cross-domain transfer request — inbound NMBS assertion binding is mandatory.
#[derive(Clone, Debug, PartialEq)]
pub struct CrossDomainTransfer {
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub label: ConfidentialityLabel,
    pub payload: String,
    pub inbound_binding: BindingDataObject,
    pub nmb_signing_key: SigningKey,
    pub nmb_verifying_key: VerifyingKey,
    pub kas_signing_key: SigningKey,
    pub kas_verifying_key: VerifyingKey,
}

impl CrossDomainTransfer {
    pub fn execute(
        &self,
        guard: &CrossDomainGuard,
        audit: &AuditLog,
    ) -> LabelResult<TransferOutcome> {
        validate_domain_pair(&self.source_domain, &self.target_domain)?;
        let fail_closed = guard.is_accredited();

        if self.inbound_binding.binding.method != BindingMethod::Assertion {
            let record = AuditRecord::new(
                AuditEventKind::BindingReject,
                "cross-domain-guard",
                self.label.clone(),
                "mandatory-assertion-binding",
                "deny",
                "embedded-only bindings rejected at cross-domain boundary",
            )
            .with_domains(self.source_domain.clone(), self.target_domain.clone())
            .with_payload_digest(sha256_base64(self.payload.as_bytes()));
            record_audit(audit, record, fail_closed)?;
            return Err(LabelError::CrossDomain(
                "cross-domain transfer requires STANAG 4778 assertion binding".into(),
            ));
        }

        self.inbound_binding.verify(
            self.payload.as_bytes(),
            Some(&self.nmb_verifying_key),
        )?;

        let evaluate_record = AuditRecord::new(
            AuditEventKind::CrossDomainEvaluate,
            "cross-domain-guard",
            self.label.clone(),
            "pre-guard-binding-verified",
            "evaluate",
            "inbound NMBS assertion binding verified",
        )
        .with_domains(self.source_domain.clone(), self.target_domain.clone())
        .with_payload_digest(sha256_base64(self.payload.as_bytes()));
        record_audit(audit, evaluate_record, fail_closed)?;

        let result = guard.evaluate(&self.label)?;

        match result.decision {
            GuardDecision::Allow | GuardDecision::Downgrade => {
                let effective = result.effective_label.ok_or_else(|| {
                    LabelError::CrossDomain(
                        "guard approved transfer but no effective label".into(),
                    )
                })?;

                let codec = Stanag4774Codec::new();
                let label_xml = codec.serialize(&effective, Stanag4774Format::Xml)?;

                let outbound = BindingDataObject::assertion_bound(
                    effective.clone(),
                    self.payload.as_bytes(),
                    &self.nmb_signing_key,
                )?;
                outbound.verify(self.payload.as_bytes(), Some(&self.nmb_verifying_key))?;

                let ztdf = ZtdfPackage::create(
                    &effective,
                    self.payload.as_bytes().to_vec(),
                    &self.nmb_signing_key,
                    &self.nmb_verifying_key,
                    &self.kas_verifying_key,
                )?;
                ztdf.verify(&self.nmb_verifying_key, &self.kas_signing_key)?;

                let transfer_record = AuditRecord::new(
                    AuditEventKind::CrossDomainTransfer,
                    "cross-domain-guard",
                    self.label.clone(),
                    result.reason.clone(),
                    match result.decision {
                        GuardDecision::Allow => "allow",
                        GuardDecision::Downgrade => "downgrade",
                        GuardDecision::Deny => "deny",
                    },
                    "cross-domain transfer released",
                )
                .with_domains(self.source_domain.clone(), self.target_domain.clone())
                .with_effective_label(effective)
                .with_payload_digest(sha256_base64(self.payload.as_bytes()));
                record_audit(audit, transfer_record, fail_closed)?;

                Ok(TransferOutcome::Released {
                    label_xml,
                    payload: self.payload.clone(),
                    ztdf_manifest: Some(ztdf.manifest_json()?),
                    ztdf_package_zip: Some(ztdf.to_zip_bytes()?),
                })
            }
            GuardDecision::Deny => {
                let record = AuditRecord::new(
                    AuditEventKind::CrossDomainTransfer,
                    "cross-domain-guard",
                    self.label.clone(),
                    result.reason.clone(),
                    "deny",
                    "cross-domain transfer denied by guard",
                )
                .with_domains(self.source_domain.clone(), self.target_domain.clone());
                record_audit(audit, record, fail_closed)?;
                Ok(TransferOutcome::Denied {
                    reason: result.reason,
                })
            }
        }
    }

    pub fn guard_result(&self, guard: &CrossDomainGuard) -> LabelResult<GuardResult> {
        guard.evaluate(&self.label)
    }
}

fn record_audit(
    audit: &AuditLog,
    record: AuditRecord,
    fail_closed: bool,
) -> LabelResult<()> {
    match audit.record(record) {
        Ok(()) => Ok(()),
        Err(err) if fail_closed => Err(LabelError::CrossDomain(format!(
            "accredited guard audit unavailable: {err}"
        ))),
        Err(_) => Ok(()),
    }
}
