use mim_crypto::{sha256_base64, sign_nmb_binding, verify_nmb_binding, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::record::AuditRecord;

/// Tamper-evident audit envelope with hash chain and optional NMBS signature.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEnvelope {
    pub record: AuditRecord,
    pub previous_hash: String,
    pub record_hash: String,
    pub signature: Option<AuditSignature>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSignature {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

impl AuditEnvelope {
    pub fn seal(record: AuditRecord, previous_hash: &str) -> Self {
        let record_hash = Self::hash_record(&record, previous_hash);
        Self {
            record,
            previous_hash: previous_hash.to_owned(),
            record_hash,
            signature: None,
        }
    }

    pub fn sign(mut self, signing_key: &SigningKey) -> Result<Self, String> {
        let sig = sign_nmb_binding(signing_key, b"audit-record", &self.record_hash)
            .map_err(|e| e.to_string())?;
        self.signature = Some(AuditSignature {
            algorithm: mim_crypto::NMBS_ALGORITHM.to_owned(),
            key_id: signing_key.key_id.clone(),
            signature: sig,
        });
        Ok(self)
    }

    pub fn verify_chain(&self, expected_previous: &str) -> Result<(), String> {
        if self.previous_hash != expected_previous {
            return Err("audit chain previous hash mismatch".into());
        }
        let expected = Self::hash_record(&self.record, &self.previous_hash);
        if expected != self.record_hash {
            return Err("audit record hash mismatch".into());
        }
        Ok(())
    }

    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), String> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| "audit envelope is not signed".to_string())?;
        if signature.key_id != verifying_key.key_id {
            return Err(format!(
                "audit signature key id mismatch: expected {}, got {}",
                verifying_key.key_id, signature.key_id
            ));
        }
        verify_nmb_binding(
            verifying_key,
            b"audit-record",
            &self.record_hash,
            &signature.signature,
        )
        .map_err(|e| e.to_string())
    }

    pub fn to_json_line(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    pub fn from_json_line(line: &str) -> Result<Self, String> {
        serde_json::from_str(line).map_err(|e| e.to_string())
    }

    pub fn hash_record(record: &AuditRecord, previous_hash: &str) -> String {
        let payload = serde_json::to_string(record).unwrap_or_default();
        sha256_base64(format!("{previous_hash}|{payload}").as_bytes())
    }
}

/// Export audit envelopes for SIEM / log aggregation (CEF-style JSON array).
pub fn export_siem_json(envelopes: &[AuditEnvelope]) -> Result<String, String> {
    let events: Vec<serde_json::Value> = envelopes
        .iter()
        .map(|env| {
            serde_json::json!({
                "vendor": "AINextGenC2",
                "product": "mim-audit",
                "version": "1.0",
                "eventKind": env.record.event_kind,
                "subjectId": env.record.subject_id,
                "decision": env.record.decision,
                "reason": env.record.reason,
                "policyRuleId": env.record.policy_rule_id,
                "timestamp": env.record.timestamp,
                "recordHash": env.record_hash,
                "previousHash": env.previous_hash,
                "signed": env.signature.is_some(),
            })
        })
        .collect();
    serde_json::to_string_pretty(&events).map_err(|e| e.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_crypto::conformance_keypair;
    use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};

    use super::*;
    use crate::record::AuditEventKind;

    #[test]
    fn audit_chain_and_signature_roundtrip() {
        let keys = conformance_keypair().expect("keys");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let record = AuditRecord::new(
            AuditEventKind::CrossDomainEvaluate,
            "guard",
            label,
            "spif-nato",
            "downgrade",
            "secret to restricted",
        );
        let env = AuditEnvelope::seal(record, "GENESIS")
            .sign(keys.signing_key())
            .expect("sign");
        env.verify_chain("GENESIS").expect("chain");
        env.verify_signature(keys.verifying_key()).expect("sig");
    }
}
