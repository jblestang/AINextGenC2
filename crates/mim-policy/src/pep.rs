use mim_labeling::{ConfidentialityLabel, SecurityDomain};

use crate::context::{AccessOperation, SubjectAttributes};
use crate::error::{PolicyError, PolicyResult};
use crate::pdp::{PolicyDecision, PolicyDecisionPoint, PolicyEffect};
use crate::pip::PolicyInformationPoint;

/// Policy Enforcement Point — consults PIP + PDP and enforces decisions.
#[derive(Clone, Debug)]
pub struct PolicyEnforcementPoint {
    pip: PolicyInformationPoint,
    pdp: PolicyDecisionPoint,
}

impl PolicyEnforcementPoint {
    pub fn new(pip: PolicyInformationPoint, pdp: PolicyDecisionPoint) -> Self {
        Self { pip, pdp }
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
        let context = self.pip.access_context(subject, label, operation, domain)?;
        let decision = self.pdp.evaluate(&context)?;
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
                .cross_domain_context(subject, label, source, target, mission_id)?;
        let decision = self.pdp.evaluate(&context)?;
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
            subject,
            label,
            source,
            target,
            None,
        )?;
        self.pdp.evaluate(&context)
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
}
