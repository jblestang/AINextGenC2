use mim_labeling::{ConfidentialityLabel, LabelResult, SecurityDomain};
use mim_policy::{
    PolicyDecisionPoint, PolicyEffect, PolicyEnforcementPoint, PolicyInformationPoint,
    SubjectAttributes,
};

use crate::config::DcsConfig;

/// Decision from a cross-domain guard evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardDecision {
    Allow,
    Deny,
    Downgrade,
}

/// Result of evaluating a label against a target domain.
#[derive(Clone, Debug, PartialEq)]
pub struct GuardResult {
    pub decision: GuardDecision,
    pub reason: String,
    pub effective_label: Option<ConfidentialityLabel>,
}

/// Cross-domain guard enforcing DCS label policies via the policy plane (PDP/PEP).
#[derive(Clone, Debug)]
pub struct CrossDomainGuard {
    source: SecurityDomain,
    target: SecurityDomain,
    pep: PolicyEnforcementPoint,
    accredited: bool,
}

impl CrossDomainGuard {
    pub fn new(source: SecurityDomain, target: SecurityDomain) -> Self {
        let mut pap = mim_policy::PolicyAdministrationPoint::new(mim_policy::PolicyStore::new());
        let _ = pap.register_domain(source.clone());
        let _ = pap.register_domain(target.clone());
        let _ = pap.add_cross_domain_policy(mim_policy::CrossDomainPolicy::new(
            format!("{}-to-{}", source.id.0, target.id.0),
            source.id.clone(),
            target.id.clone(),
        ));
        let store = pap.into_store();
        Self {
            source,
            target,
            pep: PolicyEnforcementPoint::new(
                PolicyInformationPoint::new(),
                PolicyDecisionPoint::new(store),
            ),
            accredited: false,
        }
    }

    pub fn from_policy_plane(
        pep: PolicyEnforcementPoint,
        source: SecurityDomain,
        target: SecurityDomain,
    ) -> Self {
        Self {
            source,
            target,
            pep,
            accredited: false,
        }
    }

    pub fn with_accredited(mut self, accredited: bool) -> Self {
        self.accredited = accredited;
        self
    }

    pub fn is_accredited(&self) -> bool {
        self.accredited
    }

    pub fn source(&self) -> &SecurityDomain {
        &self.source
    }

    pub fn target(&self) -> &SecurityDomain {
        &self.target
    }

    pub fn pep(&self) -> &PolicyEnforcementPoint {
        &self.pep
    }

    pub fn evaluate(&self, label: &ConfidentialityLabel) -> LabelResult<GuardResult> {
        self.evaluate_with_subject(label, SubjectAttributes::new("cross-domain-guard", label.classification))
    }

    pub fn evaluate_with_subject(
        &self,
        label: &ConfidentialityLabel,
        subject: SubjectAttributes,
    ) -> LabelResult<GuardResult> {
        let decision = self.pep.evaluate_cross_domain(
            subject,
            label,
            &self.source,
            &self.target,
        )?;

        Ok(map_decision(decision))
    }

    pub fn with_audit(mut self, audit: mim_audit::AuditLog) -> Self {
        self.pep = PolicyEnforcementPoint::new(
            self.pep.pip().clone(),
            PolicyDecisionPoint::new(self.pep.pdp().store().clone()),
        )
        .with_audit(audit);
        self
    }

    pub fn preset_high_to_low() -> Self {
        DcsConfig::conformance_high_to_low()
            .build_guard()
            .expect("conformance DCS config")
    }

    /// Build guard from external TOML/JSON configuration file.
    pub fn from_config_file(path: impl AsRef<std::path::Path>) -> LabelResult<Self> {
        let config = DcsConfig::load_path(path).map_err(|e| {
            mim_labeling::LabelError::CrossDomain(format!("DCS config: {e}"))
        })?;
        config.build_guard().map_err(|e| {
            mim_labeling::LabelError::CrossDomain(format!("DCS guard build: {e}"))
        })
    }

    /// Build guard from in-memory configuration (domains, SPIF paths, downgrade rules).
    pub fn from_config(config: &DcsConfig) -> LabelResult<Self> {
        config.build_guard().map_err(|e| {
            mim_labeling::LabelError::CrossDomain(format!("DCS guard build: {e}"))
        })
    }

    /// Cross-domain guard whose releasability constraints are SPIF-administered.
    pub fn from_spif_registry(registry: mim_spif::SpifRegistry) -> LabelResult<Self> {
        let pap = mim_policy::PolicyAdministrationPoint::with_spif_registry(registry.clone())
            .map_err(|e| mim_labeling::LabelError::CrossDomain(e.to_string()))?;
        let (source, target) = mim_policy::guard_domains_from_spif(
            &registry,
            "DOMAIN-HIGH",
            "DOMAIN-LOW",
        )
            .map_err(|e| mim_labeling::LabelError::CrossDomain(e.to_string()))?;
        Ok(Self::from_policy_plane(
            PolicyEnforcementPoint::new(
                PolicyInformationPoint::new(),
                PolicyDecisionPoint::new(pap.into_store()),
            ),
            source,
            target,
        ))
    }

    pub fn preset_coalition() -> Self {
        let pep = PolicyEnforcementPoint::new(
            PolicyInformationPoint::new(),
            PolicyDecisionPoint::new(mim_policy::PolicyStore::preset_coalition()),
        );
        Self::from_policy_plane(
            pep,
            SecurityDomain::new("DOMAIN-NATO", "NATO Core", mim_labeling::ClassificationLevel::Secret)
                .with_releasable_to(vec![
                    "USA".into(),
                    "GBR".into(),
                    "DEU".into(),
                    "FRA".into(),
                ]),
            SecurityDomain::new(
                "DOMAIN-PARTNER",
                "Partner Nation",
                mim_labeling::ClassificationLevel::Secret,
            )
            .with_releasable_to(vec!["USA".into(), "GBR".into()]),
        )
    }
}

fn map_decision(decision: mim_policy::PolicyDecision) -> GuardResult {
    let (guard_decision, effective_label) = match decision.effect {
        PolicyEffect::Permit => (GuardDecision::Allow, decision.effective_label),
        PolicyEffect::Deny => (GuardDecision::Deny, None),
        PolicyEffect::Downgrade => (GuardDecision::Downgrade, decision.effective_label),
    };

    GuardResult {
        decision: guard_decision,
        reason: decision.reason,
        effective_label,
    }
}

pub fn validate_domain_pair(source: &mim_labeling::DomainId, target: &mim_labeling::DomainId) -> LabelResult<()> {
    SecurityDomain::validate_id(&source.0)?;
    SecurityDomain::validate_id(&target.0)?;
    if source.0 == target.0 {
        return Err(mim_labeling::LabelError::CrossDomain(
            "source and target domains must differ for cross-domain transfer".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{CategoryMarking, LabelPolicy};

    use super::*;

    #[test]
    fn allows_matching_label() {
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), mim_labeling::ClassificationLevel::Restricted)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Allow);
    }

    #[test]
    fn downgrades_secret_to_restricted() {
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), mim_labeling::ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Downgrade);
        assert_eq!(
            result.effective_label.expect("label").classification,
            mim_labeling::ClassificationLevel::Restricted
        );
    }

    #[test]
    fn restricted_label_allowed_on_low_domain() {
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), mim_labeling::ClassificationLevel::Restricted)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Allow);
    }

    #[test]
    fn denies_deu_on_low_domain() {
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), mim_labeling::ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["DEU".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Deny);
    }

    #[test]
    fn denies_unauthorized_releasability() {
        let guard = CrossDomainGuard::preset_coalition();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), mim_labeling::ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["DEU".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Deny);
    }
}
