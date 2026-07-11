use mim_labeling::{ClassificationLevel, ConfidentialityLabel, SecurityDomain};

use crate::context::{AccessOperation, PolicyContext};
use crate::error::{PolicyError, PolicyResult};
use crate::store::PolicyStore;

/// Policy decision effect.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PolicyEffect {
    Permit,
    Deny,
    Downgrade,
}

/// Result of PDP evaluation.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    pub reason: String,
    pub effective_label: Option<ConfidentialityLabel>,
}

impl PolicyDecision {
    pub fn permit(reason: impl Into<String>, label: ConfidentialityLabel) -> Self {
        Self {
            effect: PolicyEffect::Permit,
            reason: reason.into(),
            effective_label: Some(label),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            effect: PolicyEffect::Deny,
            reason: reason.into(),
            effective_label: None,
        }
    }

    pub fn downgrade(
        reason: impl Into<String>,
        label: ConfidentialityLabel,
    ) -> Self {
        Self {
            effect: PolicyEffect::Downgrade,
            reason: reason.into(),
            effective_label: Some(label),
        }
    }
}

/// Policy Decision Point — evaluates context against stored policies.
#[derive(Clone, Debug)]
pub struct PolicyDecisionPoint {
    store: PolicyStore,
}

impl PolicyDecisionPoint {
    pub fn new(store: PolicyStore) -> Self {
        Self { store }
    }

    pub fn from_preset_high_to_low() -> Self {
        Self::new(PolicyStore::preset_high_to_low())
    }

    pub fn store(&self) -> &PolicyStore {
        &self.store
    }

    pub fn evaluate(&self, context: &PolicyContext) -> PolicyResult<PolicyDecision> {
        match context.environment.operation {
            AccessOperation::CrossDomainTransfer => self.evaluate_cross_domain(context),
            AccessOperation::Read | AccessOperation::Write | AccessOperation::Delete => {
                self.evaluate_access(context)
            }
        }
    }

    fn evaluate_access(&self, context: &PolicyContext) -> PolicyResult<PolicyDecision> {
        let domain = self.require_domain(&context.environment.source_domain)?;

        if let Some(deny) = self.check_handling_caveats(&context.subject, &context.resource) {
            return Ok(deny);
        }

        if let Some(deny) = self.check_mission_compartment(
            resolve_mission_id(&context.subject, &context.environment),
            domain,
            None,
        ) {
            return Ok(deny);
        }

        if context.subject.clearance < context.resource.classification {
            return Ok(PolicyDecision::deny(format!(
                "subject clearance {} insufficient for resource classification {}",
                context.subject.clearance.as_stanag_str(),
                context.resource.classification.as_stanag_str()
            )));
        }

        if domain.max_classification < context.resource.classification {
            return Ok(PolicyDecision::deny(format!(
                "resource classification {} exceeds domain max {}",
                context.resource.classification.as_stanag_str(),
                domain.max_classification.as_stanag_str()
            )));
        }

        if let Some(nationality) = &context.subject.nationality {
            if !context.resource.releasable_countries.is_empty()
                && !context
                    .resource
                    .releasable_countries
                    .iter()
                    .any(|country| country == nationality)
            {
                return Ok(PolicyDecision::deny(format!(
                    "subject nationality {nationality} not in resource releasability"
                )));
            }
            if !domain.accepts_country(nationality) {
                return Ok(PolicyDecision::deny(format!(
                    "subject nationality {nationality} not accepted in domain {}",
                    domain.id.0
                )));
            }
        }

        for country in &context.resource.releasable_countries {
            if !domain.accepts_country(country) {
                return Ok(PolicyDecision::deny(format!(
                    "releasability to {country} not permitted in domain {}",
                    domain.id.0
                )));
            }
        }

        Ok(PolicyDecision::permit(
            format!(
                "{} permitted for subject {} in domain {}",
                operation_name(context.environment.operation),
                context.subject.subject_id,
                domain.id.0
            ),
            context.label.clone(),
        ))
    }

    fn evaluate_cross_domain(&self, context: &PolicyContext) -> PolicyResult<PolicyDecision> {
        let target_id = context.environment.target_domain.as_ref().ok_or_else(|| {
            PolicyError::Invalid("cross-domain evaluation requires target domain".into())
        })?;

        let _policy = self.store.policy_for_pair(
            &context.environment.source_domain,
            target_id,
        ).ok_or_else(|| {
            PolicyError::NotFound(format!(
                "no cross-domain policy for {} -> {}",
                context.environment.source_domain.0, target_id.0
            ))
        })?;

        let source = self.require_domain(&context.environment.source_domain)?;
        let target = self.require_domain(target_id)?;

        if let Some(deny) = self.check_handling_caveats(&context.subject, &context.resource) {
            return Ok(deny);
        }

        let mission_id = resolve_mission_id(&context.subject, &context.environment);
        if let Some(deny) = self.check_mission_compartment(mission_id, source, Some(target)) {
            return Ok(deny);
        }

        for country in &context.resource.releasable_countries {
            if !target.accepts_country(country) {
                return Ok(PolicyDecision::deny(format!(
                    "releasability to {country} not permitted in target domain {}",
                    target.id.0
                )));
            }
        }

        if context.label.classification > target.max_classification {
            if target.max_classification >= ClassificationLevel::Unclassified {
                let downgraded = crate::downgrade::downgraded_label_for_target(
                    &context.label,
                    target,
                    self.store.downgrade_config(),
                )?;
                return Ok(PolicyDecision::downgrade(
                    format!(
                        "classification {} exceeds target domain max {}; downgrading to {} with category intersection",
                        context.label.classification.as_stanag_str(),
                        target.max_classification.as_stanag_str(),
                        downgraded.classification.as_stanag_str()
                    ),
                    downgraded,
                ));
            }
            return Ok(PolicyDecision::deny(format!(
                "classification {} exceeds target domain max {}",
                context.label.classification.as_stanag_str(),
                target.max_classification.as_stanag_str()
            )));
        }

        Ok(PolicyDecision::permit(
            format!(
                "cross-domain transfer permitted from {} to {}",
                context.environment.source_domain.0, target.id.0
            ),
            context.label.clone(),
        ))
    }

    fn require_domain(
        &self,
        id: &mim_labeling::DomainId,
    ) -> PolicyResult<&SecurityDomain> {
        self.store
            .domain(id)
            .ok_or_else(|| PolicyError::NotFound(format!("domain '{}' not registered", id.0)))
    }

    fn check_handling_caveats(
        &self,
        subject: &crate::context::SubjectAttributes,
        resource: &crate::context::ResourceAttributes,
    ) -> Option<PolicyDecision> {
        for caveat in &resource.handling_caveats {
            if !subject.holds_caveat(caveat) {
                return Some(PolicyDecision::deny(format!(
                    "subject {} lacks required handling caveat {caveat}",
                    subject.subject_id
                )));
            }
        }
        None
    }

    fn check_mission_compartment(
        &self,
        mission_id: Option<&str>,
        source: &SecurityDomain,
        target: Option<&SecurityDomain>,
    ) -> Option<PolicyDecision> {
        let requires_mission = !source.mission_compartments.is_empty()
            || target
                .map(|domain| !domain.mission_compartments.is_empty())
                .unwrap_or(false);

        if !requires_mission {
            return None;
        }

        let Some(mission_id) = mission_id else {
            return Some(PolicyDecision::deny(
                "mission compartment required for compartmented domain transfer",
            ));
        };

        if !source.accepts_mission(mission_id) {
            return Some(PolicyDecision::deny(format!(
                "mission {mission_id} not authorized in source domain {}",
                source.id.0
            )));
        }

        if let Some(target) = target {
            if !target.accepts_mission(mission_id) {
                return Some(PolicyDecision::deny(format!(
                    "mission {mission_id} not authorized in target domain {}",
                    target.id.0
                )));
            }
        }

        None
    }
}

fn resolve_mission_id<'a>(
    subject: &'a crate::context::SubjectAttributes,
    environment: &'a crate::context::EnvironmentAttributes,
) -> Option<&'a str> {
    environment
        .mission_id
        .as_deref()
        .or(subject.mission_id.as_deref())
}

fn operation_name(operation: AccessOperation) -> &'static str {
    match operation {
        AccessOperation::Read => "read",
        AccessOperation::Write => "write",
        AccessOperation::Delete => "delete",
        AccessOperation::CrossDomainTransfer => "cross-domain transfer",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{CategoryMarking, DomainId, LabelPolicy};

    use crate::context::{
        EnvironmentAttributes, ResourceAttributes, SubjectAttributes,
    };
    use crate::store::PolicyStore;

    use super::*;

    fn cross_domain_context(label: ConfidentialityLabel) -> PolicyContext {
        PolicyContext {
            subject: SubjectAttributes::new("guard", ClassificationLevel::Secret),
            resource: ResourceAttributes::from_label(&label),
            environment: EnvironmentAttributes::cross_domain(
                DomainId::new("DOMAIN-HIGH"),
                DomainId::new("DOMAIN-LOW"),
                None,
            ),
            label,
        }
    }

    #[test]
    fn downgrades_secret_for_low_domain() {
        let pdp = PolicyDecisionPoint::from_preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let decision = pdp.evaluate(&cross_domain_context(label)).expect("decision");
        assert_eq!(decision.effect, PolicyEffect::Downgrade);
    }

    #[test]
    fn denies_unauthorized_releasability() {
        let pdp = PolicyDecisionPoint::from_preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["DEU".into()]));
        let decision = pdp.evaluate(&cross_domain_context(label)).expect("decision");
        assert_eq!(decision.effect, PolicyEffect::Deny);
    }

    #[test]
    fn denies_insufficient_clearance_on_read() {
        let pdp = PolicyDecisionPoint::from_preset_high_to_low();
        let pip = crate::pip::PolicyInformationPoint::new();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let domain = pdp
            .store()
            .domain(&DomainId::new("DOMAIN-HIGH"))
            .expect("domain")
            .clone();
        let ctx = pip
            .access_context(
                SubjectAttributes::new("analyst", ClassificationLevel::Restricted),
                &label,
                AccessOperation::Read,
                &domain,
            )
            .expect("ctx");
        let decision = pdp.evaluate(&ctx).expect("decision");
        assert_eq!(decision.effect, PolicyEffect::Deny);
    }

    #[test]
    fn denies_missing_handling_caveat() {
        let pdp = PolicyDecisionPoint::from_preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]))
            .with_category(CategoryMarking::handling_caveat("LOCSEN"));
        let decision = pdp
            .evaluate(&cross_domain_context(label))
            .expect("decision");
        assert_eq!(decision.effect, PolicyEffect::Deny);
        assert!(decision.reason.contains("LOCSEN"));
    }

    #[test]
    fn permits_matching_handling_caveat() {
        let pdp = PolicyDecisionPoint::from_preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Restricted)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]))
            .with_category(CategoryMarking::handling_caveat("LOCSEN"));
        let mut ctx = cross_domain_context(label);
        ctx.subject = SubjectAttributes::new("guard", ClassificationLevel::Secret)
            .with_handling_caveat("LOCSEN");
        let decision = pdp.evaluate(&ctx).expect("decision");
        assert_eq!(decision.effect, PolicyEffect::Permit);
    }

    #[test]
    fn denies_missing_mission_compartment() {
        let mut store = PolicyStore::preset_high_to_low();
        let source = store
            .domain(&DomainId::new("DOMAIN-HIGH"))
            .expect("source")
            .clone()
            .with_mission_compartments(vec!["SAR-OPS-1".into()]);
        store.insert_domain(source).expect("insert");
        let pdp = PolicyDecisionPoint::new(store);
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Restricted)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let decision = pdp.evaluate(&cross_domain_context(label)).expect("decision");
        assert_eq!(decision.effect, PolicyEffect::Deny);
        assert!(decision.reason.contains("mission compartment"));
    }

    #[test]
    fn permits_matching_mission_compartment() {
        let mut store = PolicyStore::preset_high_to_low();
        let source = store
            .domain(&DomainId::new("DOMAIN-HIGH"))
            .expect("source")
            .clone()
            .with_mission_compartments(vec!["SAR-OPS-1".into()]);
        let target = store
            .domain(&DomainId::new("DOMAIN-LOW"))
            .expect("target")
            .clone()
            .with_mission_compartments(vec!["SAR-OPS-1".into()]);
        store.insert_domain(source).expect("insert source");
        store.insert_domain(target).expect("insert target");
        let pdp = PolicyDecisionPoint::new(store);
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Restricted)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let mut ctx = cross_domain_context(label);
        ctx.environment.mission_id = Some("SAR-OPS-1".into());
        let decision = pdp.evaluate(&ctx).expect("decision");
        assert_eq!(decision.effect, PolicyEffect::Permit);
    }
}
