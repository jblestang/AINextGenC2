use mim_labeling::{
    ClassificationLevel, ConfidentialityLabel, DomainId, LabelError, LabelResult, SecurityDomain,
};

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

/// Cross-domain guard enforcing DCS label policies.
#[derive(Clone, Debug)]
pub struct CrossDomainGuard {
    source: SecurityDomain,
    target: SecurityDomain,
}

impl CrossDomainGuard {
    pub fn new(source: SecurityDomain, target: SecurityDomain) -> Self {
        Self { source, target }
    }

    pub fn source(&self) -> &SecurityDomain {
        &self.source
    }

    pub fn target(&self) -> &SecurityDomain {
        &self.target
    }

    pub fn evaluate(&self, label: &ConfidentialityLabel) -> LabelResult<GuardResult> {
        label.validate()?;

        for country in label.releasable_countries() {
            if !self.target.accepts_country(&country) {
                return Ok(GuardResult {
                    decision: GuardDecision::Deny,
                    reason: format!(
                        "releasability to {country} not permitted in target domain {}",
                        self.target.id.0
                    ),
                    effective_label: None,
                });
            }
        }

        if label.classification > self.target.max_classification {
            if self.target.max_classification >= ClassificationLevel::Unclassified {
                let mut downgraded = label.clone();
                downgraded.classification = self.target.max_classification;
                return Ok(GuardResult {
                    decision: GuardDecision::Downgrade,
                    reason: format!(
                        "classification {} exceeds target domain max {}; downgrading to {}",
                        label.classification.as_stanag_str(),
                        self.target.max_classification.as_stanag_str(),
                        downgraded.classification.as_stanag_str()
                    ),
                    effective_label: Some(downgraded),
                });
            }
            return Ok(GuardResult {
                decision: GuardDecision::Deny,
                reason: format!(
                    "classification {} exceeds target domain max {}",
                    label.classification.as_stanag_str(),
                    self.target.max_classification.as_stanag_str()
                ),
                effective_label: None,
            });
        }

        Ok(GuardResult {
            decision: GuardDecision::Allow,
            reason: format!(
                "label permitted from {} to {}",
                self.source.id.0, self.target.id.0
            ),
            effective_label: Some(label.clone()),
        })
    }

    pub fn preset_high_to_low() -> Self {
        Self::new(
            SecurityDomain::new("DOMAIN-HIGH", "High Side", ClassificationLevel::Secret)
                .with_releasable_to(vec!["USA".into(), "GBR".into(), "DEU".into()]),
            SecurityDomain::new("DOMAIN-LOW", "Low Side", ClassificationLevel::Restricted)
                .with_releasable_to(vec!["USA".into(), "GBR".into()]),
        )
    }

    pub fn preset_coalition() -> Self {
        Self::new(
            SecurityDomain::new("DOMAIN-NATO", "NATO Core", ClassificationLevel::Secret)
                .with_releasable_to(vec![
                    "USA".into(),
                    "GBR".into(),
                    "DEU".into(),
                    "FRA".into(),
                ]),
            SecurityDomain::new("DOMAIN-PARTNER", "Partner Nation", ClassificationLevel::Secret)
                .with_releasable_to(vec!["USA".into(), "GBR".into()]),
        )
    }
}

pub fn validate_domain_pair(source: &DomainId, target: &DomainId) -> LabelResult<()> {
    SecurityDomain::validate_id(&source.0)?;
    SecurityDomain::validate_id(&target.0)?;
    if source.0 == target.0 {
        return Err(LabelError::CrossDomain(
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
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Restricted)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Allow);
    }

    #[test]
    fn downgrades_secret_to_restricted() {
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Downgrade);
        assert_eq!(
            result.effective_label.expect("label").classification,
            ClassificationLevel::Restricted
        );
    }

    #[test]
    fn restricted_label_allowed_on_low_domain() {
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Restricted)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Allow);
    }

    #[test]
    fn denies_deu_on_low_domain() {
        let guard = CrossDomainGuard::preset_high_to_low();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["DEU".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Deny);
    }

    #[test]
    fn denies_unauthorized_releasability() {
        let guard = CrossDomainGuard::preset_coalition();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["DEU".into()]));
        let result = guard.evaluate(&label).expect("eval");
        assert_eq!(result.decision, GuardDecision::Deny);
    }
}
