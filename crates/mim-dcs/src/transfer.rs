use mim_audit::{AuditEventKind, AuditLog, AuditRecord};
use mim_crypto::{sha256_base64, SigningKey, VerifyingKey};
use mim_labeling::{ConfidentialityLabel, DomainId, LabelError, LabelResult};
use mim_policy::SubjectAttributes;
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use mim_stanag4778::{BindingDataObject, BindingMethod};
use mim_ztdf::{KasClient, ZtdfPackage};
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
                ztdf.verify_release(
                    &self.nmb_verifying_key,
                    self.payload.as_bytes(),
                )?;

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

    /// Target-side ZTDF receive using a local KAS signing key (lab / conformance).
    pub fn receive_ztdf_on_target_with_key(
        subject: &SubjectAttributes,
        guard: &CrossDomainGuard,
        zip: &[u8],
        nmb_verifying_key: &VerifyingKey,
        kas_signing_key: &SigningKey,
        audit: &AuditLog,
    ) -> LabelResult<String> {
        let kas = mim_ztdf::LocalKasClient::new(kas_signing_key.clone());
        Self::receive_ztdf_on_target(
            subject,
            guard,
            zip,
            nmb_verifying_key,
            &kas,
            audit,
        )
    }

    /// Target-side ZTDF receive: PEP ABAC gate before KAS unwrap and payload decrypt.
    pub fn receive_ztdf_on_target(
        subject: &SubjectAttributes,
        guard: &CrossDomainGuard,
        zip: &[u8],
        nmb_verifying_key: &VerifyingKey,
        kas: &dyn KasClient,
        audit: &AuditLog,
    ) -> LabelResult<String> {
        let fail_closed = guard.is_accredited();
        let package = ZtdfPackage::from_zip_sealed(zip)?;
        let label = package.label()?;

        let evaluate_record = AuditRecord::new(
            AuditEventKind::CrossDomainEvaluate,
            subject.subject_id.clone(),
            label.clone(),
            "ztdf-decrypt-pep",
            "evaluate",
            "target-side ZTDF decrypt PEP evaluation",
        )
        .with_domains(guard.source().id.clone(), guard.target().id.clone());
        record_audit(audit, evaluate_record, fail_closed)?;

        let plaintext = package.decrypt_with_policy(
            subject,
            guard.pep(),
            guard.target(),
            kas,
        )?;

        package.verify_binding_plaintext(&plaintext, nmb_verifying_key)?;

        let transfer_record = AuditRecord::new(
            AuditEventKind::CrossDomainTransfer,
            subject.subject_id.clone(),
            label,
            "ztdf-decrypt-pep",
            "allow",
            "target-side ZTDF decrypted through PEP gate",
        )
        .with_domains(guard.source().id.clone(), guard.target().id.clone())
        .with_payload_digest(sha256_base64(&plaintext));
        record_audit(audit, transfer_record, fail_closed)?;

        String::from_utf8(plaintext).map_err(|e| LabelError::CrossDomain(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_crypto::conformance_key_ring;
    use mim_labeling::{CategoryMarking, ClassificationLevel, LabelPolicy};
    use mim_policy::SubjectAttributes;
    use mim_stanag4778::BindingDataObject;
    use mim_ztdf::LocalKasClient;

    use super::*;

    fn sample_transfer() -> (CrossDomainTransfer, CrossDomainGuard) {
        let ring = conformance_key_ring().expect("ring");
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into(), "GBR".into()]));
        let payload = r#"{"instances":[]}"#.to_owned();
        let inbound = BindingDataObject::assertion_bound(
            label.clone(),
            payload.as_bytes(),
            ring.nmb_signing(),
        )
        .expect("binding");
        let transfer = CrossDomainTransfer {
            source_domain: guard.source().id.clone(),
            target_domain: guard.target().id.clone(),
            label,
            payload: payload.clone(),
            inbound_binding: inbound,
            nmb_signing_key: ring.nmb_signing().clone(),
            nmb_verifying_key: ring.nmb_verifying().clone(),
            kas_signing_key: ring.kas_signing().clone(),
            kas_verifying_key: ring.kas_verifying().clone(),
        };
        (transfer, guard)
    }

    #[test]
    fn receive_ztdf_on_target_uses_pep_gate() {
        let ring = conformance_key_ring().expect("ring");
        let (transfer, guard) = sample_transfer();
        let audit = AuditLog::memory();
        let outcome = transfer.execute(&guard, &audit).expect("execute");
        let zip = match outcome {
            TransferOutcome::Released {
                ztdf_package_zip: Some(zip),
                ..
            } => zip,
            _ => panic!("expected released ztdf"),
        };
        let subject = SubjectAttributes::new("low-analyst", ClassificationLevel::Restricted)
            .with_nationality("USA");
        let kas = LocalKasClient::new(ring.kas_signing().clone());
        let decrypted = CrossDomainTransfer::receive_ztdf_on_target(
            &subject,
            &guard,
            &zip,
            ring.nmb_verifying(),
            &kas,
            &audit,
        )
        .expect("decrypt");
        assert_eq!(decrypted, r#"{"instances":[]}"#);
        assert!(audit.len() >= 4);
    }

    #[test]
    fn receive_ztdf_denies_insufficient_clearance() {
        let ring = conformance_key_ring().expect("ring");
        let (transfer, guard) = sample_transfer();
        let audit = AuditLog::memory();
        let outcome = transfer.execute(&guard, &audit).expect("execute");
        let zip = match outcome {
            TransferOutcome::Released {
                ztdf_package_zip: Some(zip),
                ..
            } => zip,
            _ => panic!("expected released ztdf"),
        };
        let subject = SubjectAttributes::new("uncleared", ClassificationLevel::Unclassified);
        let kas = LocalKasClient::new(ring.kas_signing().clone());
        assert!(CrossDomainTransfer::receive_ztdf_on_target(
            &subject,
            &guard,
            &zip,
            ring.nmb_verifying(),
            &kas,
            &audit,
        )
        .is_err());
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
