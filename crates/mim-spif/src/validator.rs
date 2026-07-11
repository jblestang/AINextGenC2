use mim_labeling::{ConfidentialityLabel, LabelError, LabelResult};

use crate::policy::{SpifCategoryType, SpifPolicy};
use crate::registry::SpifRegistry;

/// Validates confidentiality labels against loaded SPIF policies.
#[derive(Clone, Debug)]
pub struct SpifValidator {
    registry: SpifRegistry,
}

impl SpifValidator {
    pub fn new(registry: SpifRegistry) -> Self {
        Self { registry }
    }

    pub fn with_defaults() -> Self {
        Self::new(SpifRegistry::with_defaults())
    }

    pub fn registry(&self) -> &SpifRegistry {
        &self.registry
    }

    pub fn validate_label(&self, label: &ConfidentialityLabel) -> LabelResult<()> {
        label.validate()?;
        let policy = self.registry.policy_for_label(label).ok_or_else(|| {
            LabelError::InvalidPolicy(format!(
                "unknown SPIF policy identifier: {}",
                label.policy.identifier
            ))
        })?;
        validate_against_policy(label, policy)
    }
}

pub fn validate_against_policy(label: &ConfidentialityLabel, policy: &SpifPolicy) -> LabelResult<()> {
    let class = label.classification.as_stanag_str();
    if !policy
        .allowed_classifications
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(class))
    {
        return Err(LabelError::Validation(format!(
            "classification {class} not permitted by SPIF policy {}",
            policy.policy_id
        )));
    }

    for category in &label.categories {
        let Some(spif_cat) = policy
            .categories
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(&category.tag_name))
        else {
            return Err(LabelError::Validation(format!(
                "category '{}' not defined in SPIF policy {}",
                category.tag_name, policy.policy_id
            )));
        };

        if !spif_cat.allowed_values.is_empty() {
            for value in &category.values {
                if !spif_cat
                    .allowed_values
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(value))
                {
                    return Err(LabelError::Validation(format!(
                        "category value '{value}' not permitted for '{}'",
                        category.tag_name
                    )));
                }
            }
        }

        let expected_type = match category.category_type {
            mim_labeling::CategoryType::Restrictive => SpifCategoryType::Restrictive,
            mim_labeling::CategoryType::Permissive => SpifCategoryType::Permissive,
            mim_labeling::CategoryType::Informative => SpifCategoryType::Informative,
        };
        if spif_cat.category_type != expected_type {
            return Err(LabelError::Validation(format!(
                "category '{}' type mismatch with SPIF policy",
                category.tag_name
            )));
        }
    }

    for rule in &policy.validations {
        if !label.classification.as_stanag_str().eq_ignore_ascii_case(&rule.classification) {
            continue;
        }
        let values = label
            .categories
            .iter()
            .find(|c| c.tag_name.eq_ignore_ascii_case(&rule.category_name))
            .map(|c| c.values.clone())
            .unwrap_or_default();
        let satisfied = rule
            .required_any_of
            .iter()
            .any(|required| values.iter().any(|v| v.eq_ignore_ascii_case(required)));
        if !satisfied {
            return Err(LabelError::Validation(format!(
                "SPIF validation failed: classification {} requires category '{}' with one of {:?}",
                rule.classification, rule.category_name, rule.required_any_of
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{CategoryMarking, ClassificationLevel, LabelPolicy};

    use super::*;
    use crate::policy::SpifPolicy;

    #[test]
    fn acme_confidential_requires_releasable_to() {
        let validator = SpifValidator::with_defaults();
        let valid = ConfidentialityLabel::new(LabelPolicy::new("ACME"), ClassificationLevel::Confidential)
            .with_category(CategoryMarking::releasable_to(vec!["MOCK".into()]));
        validator.validate_label(&valid).expect("valid");

        let invalid = ConfidentialityLabel::new(LabelPolicy::new("ACME"), ClassificationLevel::Confidential)
            .with_category(CategoryMarking {
                tag_name: "Sensitive".into(),
                category_type: mim_labeling::CategoryType::Restrictive,
                values: vec!["RED".into()],
            });
        assert!(validator.validate_label(&invalid).is_err());
    }
}
