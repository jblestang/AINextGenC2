use mim_audit::{AuditEventKind, AuditLog, AuditRecord};
use mim_labeling::{ConfidentialityLabel, SecurityDomain};

use crate::context::{AccessOperation, SubjectAttributes};
use crate::error::{PolicyError, PolicyResult};
use crate::pdp::{PolicyDecision, PolicyDecisionPoint, PolicyEffect};
use crate::pip::PolicyInformationPoint;

/// Policy Enforcement Point — consults PIP + PDP and enforces decisions.
#[derive(Clone)]
pub struct PolicyEnforcementPoint {
    pip: PolicyInformationPoint,
    pdp: PolicyDecisionPoint,
    audit: Option<AuditLog>,
}

impl PolicyEnforcementPoint {
    pub fn new(pip: PolicyInformationPoint, pdp: PolicyDecisionPoint) -> Self {
        Self {
            pip,
            pdp,
            audit: None,
        }
    }

    pub fn with_audit(mut self, audit: AuditLog) -> Self {
        self.audit = Some(audit);
        self
    }

    pub fn audit(&self) -> Option<&AuditLog> {
        self.audit.as_ref()
    }

    pub fn from_preset_high_to_low() -> Self {
        Self::new(
            PolicyInformationPoint::new(),
            PolicyDecisionPoint::from_preset_high_to_low(),
        )
    }

    pub fn pip(&self) -> &PolicyInformationPoint {
        &self.pip
    }

    pub fn pdp(&self) -> &PolicyDecisionPoint {
        &self.pdp
    }

    pub fn enforce_access(
        &self,
        subject: SubjectAttributes,
        label: &ConfidentialityLabel,
        operation: AccessOperation,
        domain: &SecurityDomain,
    ) -> PolicyResult<PolicyDecision> {
        let context = self.pip.access_context(subject.clone(), label, operation, domain)?;
        let decision = self.pdp.evaluate(&context)?;
        self.record_access_audit(&subject, label, domain, operation, &decision);
        if decision.effect == PolicyEffect::Deny {
            return Err(PolicyError::Denied(decision.reason));
        }
        Ok(decision)
    }

    pub fn enforce_cross_domain(
        &self,
        subject: SubjectAttributes,
        label: &ConfidentialityLabel,
        source: &SecurityDomain,
        target: &SecurityDomain,
        mission_id: Option<String>,
    ) -> PolicyResult<PolicyDecision> {
        let context =
            self.pip
                .cross_domain_context(subject.clone(), label, source, target, mission_id)?;
        let decision = self.pdp.evaluate(&context)?;
        self.record_cross_domain_audit(&subject, label, source, target, &decision);
        if decision.effect == PolicyEffect::Deny {
            return Err(PolicyError::Denied(decision.reason));
        }
        Ok(decision)
    }

    pub fn evaluate_cross_domain(
        &self,
        subject: SubjectAttributes,
        label: &ConfidentialityLabel,
        source: &SecurityDomain,
        target: &SecurityDomain,
    ) -> PolicyResult<PolicyDecision> {
        let context = self.pip.cross_domain_context(
            subject.clone(),
            label,
            source,
            target,
            None,
        )?;
        let decision = self.pdp.evaluate(&context)?;
        self.record_cross_domain_audit(&subject, label, source, target, &decision);
        Ok(decision)
    }

    fn record_access_audit(
        &self,
        subject: &SubjectAttributes,
        label: &ConfidentialityLabel,
        domain: &SecurityDomain,
        operation: AccessOperation,
        decision: &PolicyDecision,
    ) {
        let Some(audit) = &self.audit else {
            return;
        };
        let mut record = AuditRecord::new(
            AuditEventKind::TransportAccess,
            subject.subject_id.clone(),
            label.clone(),
            "pep-access",
            effect_to_decision(decision.effect),
            decision.reason.clone(),
        )
        .with_domains(domain.id.clone(), domain.id.clone());
        if let Some(effective) = &decision.effective_label {
            record = record.with_effective_label(effective.clone());
        }
        let _ = audit.record(record);
        let _ = operation;
    }

    fn record_cross_domain_audit(
        &self,
        subject: &SubjectAttributes,
        label: &ConfidentialityLabel,
        source: &SecurityDomain,
        target: &SecurityDomain,
        decision: &PolicyDecision,
    ) {
        let Some(audit) = &self.audit else {
            return;
        };
        let mut record = AuditRecord::new(
            AuditEventKind::CrossDomainEvaluate,
            subject.subject_id.clone(),
            label.clone(),
            "pep-cross-domain",
            effect_to_decision(decision.effect),
            decision.reason.clone(),
        )
        .with_domains(source.id.clone(), target.id.clone());
        if let Some(effective) = &decision.effective_label {
            record = record.with_effective_label(effective.clone());
        }
        let _ = audit.record(record);
    }
}

fn effect_to_decision(effect: PolicyEffect) -> &'static str {
    match effect {
        PolicyEffect::Permit => "allow",
        PolicyEffect::Deny => "deny",
        PolicyEffect::Downgrade => "downgrade",
    }
}

impl std::fmt::Debug for PolicyEnforcementPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEnforcementPoint")
            .field("pip", &self.pip)
            .field("pdp", &self.pdp)
            .field("audit", &self.audit.as_ref().map(|_| "configured"))
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{CategoryMarking, ClassificationLevel, DomainId, LabelPolicy};

    use super::*;

    #[test]
    fn pep_denies_insufficient_clearance() {
        let pep = PolicyEnforcementPoint::from_preset_high_to_low();
        let domain = pep
            .pdp()
            .store()
            .domain(&DomainId::new("DOMAIN-HIGH"))
            .expect("domain")
            .clone();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let err = pep
            .enforce_access(
                SubjectAttributes::new("analyst", ClassificationLevel::Restricted),
                &label,
                AccessOperation::Read,
                &domain,
            )
            .expect_err("deny");
        assert!(matches!(err, PolicyError::Denied(_)));
    }

    #[test]
    fn pep_permits_matching_cross_domain_transfer() {
        let pep = PolicyEnforcementPoint::from_preset_high_to_low();
        let source = pep
            .pdp()
            .store()
            .domain(&DomainId::new("DOMAIN-HIGH"))
            .expect("source")
            .clone();
        let target = pep
            .pdp()
            .store()
            .domain(&DomainId::new("DOMAIN-LOW"))
            .expect("target")
            .clone();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Restricted)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let decision = pep
            .enforce_cross_domain(
                SubjectAttributes::new("guard", ClassificationLevel::Secret),
                &label,
                &source,
                &target,
                None,
            )
            .expect("permit");
        assert_eq!(decision.effect, PolicyEffect::Permit);
    }

    #[test]
    fn pep_audit_records_cross_domain_evaluation() {
        let audit = mim_audit::AuditLog::memory();
        let pep = PolicyEnforcementPoint::from_preset_high_to_low().with_audit(audit.clone());
        let source = pep
            .pdp()
            .store()
            .domain(&DomainId::new("DOMAIN-HIGH"))
            .expect("source")
            .clone();
        let target = pep
            .pdp()
            .store()
            .domain(&DomainId::new("DOMAIN-LOW"))
            .expect("target")
            .clone();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        pep.evaluate_cross_domain(
            SubjectAttributes::new("guard", ClassificationLevel::Secret),
            &label,
            &source,
            &target,
        )
        .expect("evaluate");
        assert_eq!(audit.len(), 1);
    }
}
