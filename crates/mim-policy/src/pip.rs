use mim_labeling::{ConfidentialityLabel, DomainId, SecurityDomain};
use mim_model::SecurityClassification;

use crate::context::{
    AccessOperation, EnvironmentAttributes, PolicyContext, ResourceAttributes, SubjectAttributes,
};
use crate::error::{PolicyError, PolicyResult};

/// Policy Information Point — assembles evaluation context from attributes.
#[derive(Clone, Debug, Default)]
pub struct PolicyInformationPoint;

impl PolicyInformationPoint {
    pub fn new() -> Self {
        Self
    }

    /// Build a local access-control context for transport operations.
    pub fn access_context(
        &self,
        subject: SubjectAttributes,
        label: &ConfidentialityLabel,
        operation: AccessOperation,
        domain: &SecurityDomain,
    ) -> PolicyResult<PolicyContext> {
        label.validate()?;
        Ok(PolicyContext {
            subject,
            resource: ResourceAttributes::from_label(label),
            environment: EnvironmentAttributes::local(operation, domain.id.clone()),
            label: label.clone(),
        })
    }

    /// Build a cross-domain transfer context.
    pub fn cross_domain_context(
        &self,
        subject: SubjectAttributes,
        label: &ConfidentialityLabel,
        source: &SecurityDomain,
        target: &SecurityDomain,
        mission_id: Option<String>,
    ) -> PolicyResult<PolicyContext> {
        label.validate()?;
        if source.id == target.id {
            return Err(PolicyError::Invalid(
                "source and target domains must differ for cross-domain transfer".into(),
            ));
        }
        Ok(PolicyContext {
            subject,
            resource: ResourceAttributes::from_label(label),
            environment: EnvironmentAttributes::cross_domain(
                source.id.clone(),
                target.id.clone(),
                mission_id,
            ),
            label: label.clone(),
        })
    }

    /// Derive a confidentiality label from MIM instance security metadata.
    pub fn label_from_security(security: &SecurityClassification) -> PolicyResult<ConfidentialityLabel> {
        if security.classification.is_present() {
            return ConfidentialityLabel::from_mim_security(security).map_err(PolicyError::from);
        }
        Ok(ConfidentialityLabel::new(
            mim_labeling::LabelPolicy::nato(),
            mim_labeling::ClassificationLevel::Unclassified,
        ))
    }

    /// Resolve a security domain by id from a slice of registered domains.
    pub fn resolve_domain<'a>(
        domains: &'a [SecurityDomain],
        id: &DomainId,
    ) -> PolicyResult<&'a SecurityDomain> {
        domains
            .iter()
            .find(|domain| domain.id == *id)
            .ok_or_else(|| PolicyError::NotFound(format!("domain '{}' not registered", id.0)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{CategoryMarking, ClassificationLevel, LabelPolicy};

    use super::*;

    #[test]
    fn builds_access_context() {
        let pip = PolicyInformationPoint::new();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let domain = SecurityDomain::new("DOMAIN-A", "A", ClassificationLevel::Secret);
        let ctx = pip
            .access_context(
                SubjectAttributes::new("operator-1", ClassificationLevel::Secret),
                &label,
                AccessOperation::Read,
                &domain,
            )
            .expect("ctx");
        assert_eq!(ctx.resource.classification, ClassificationLevel::Secret);
    }
}
