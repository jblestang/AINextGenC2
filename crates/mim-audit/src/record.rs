use chrono::{DateTime, Utc};
use mim_labeling::{ConfidentialityLabel, DomainId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Kind of auditable security event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuditEventKind {
    CrossDomainEvaluate,
    CrossDomainTransfer,
    TransportAccess,
    BindingVerify,
    BindingReject,
}

/// Immutable audit record for guard and PEP decisions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_kind: AuditEventKind,
    pub subject_id: String,
    pub source_domain: Option<DomainId>,
    pub target_domain: Option<DomainId>,
    pub original_label: ConfidentialityLabel,
    pub effective_label: Option<ConfidentialityLabel>,
    pub policy_rule_id: String,
    pub decision: String,
    pub reason: String,
    pub payload_digest: Option<String>,
}

impl AuditRecord {
    pub fn new(
        event_kind: AuditEventKind,
        subject_id: impl Into<String>,
        original_label: ConfidentialityLabel,
        policy_rule_id: impl Into<String>,
        decision: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_kind,
            subject_id: subject_id.into(),
            source_domain: None,
            target_domain: None,
            original_label,
            effective_label: None,
            policy_rule_id: policy_rule_id.into(),
            decision: decision.into(),
            reason: reason.into(),
            payload_digest: None,
        }
    }

    pub fn with_domains(mut self, source: DomainId, target: DomainId) -> Self {
        self.source_domain = Some(source);
        self.target_domain = Some(target);
        self
    }

    pub fn with_effective_label(mut self, label: ConfidentialityLabel) -> Self {
        self.effective_label = Some(label);
        self
    }

    pub fn with_payload_digest(mut self, digest: impl Into<String>) -> Self {
        self.payload_digest = Some(digest.into());
        self
    }
}
