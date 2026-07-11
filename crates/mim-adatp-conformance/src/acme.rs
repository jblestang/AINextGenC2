//! ADatP-4774.1 ACME SPIF semantic validation via XML-SPIF engine.

use mim_labeling::{CategoryMarking, ClassificationLevel, ConfidentialityLabel, LabelPolicy};
use mim_spif::SpifValidator;

/// ADatP-4774.1 ACME SPIF semantic validation (Figures 7 and 9).
pub fn validate_acme_semantics(label: &ConfidentialityLabel) -> Result<(), String> {
    SpifValidator::with_defaults()
        .validate_label(label)
        .map_err(|e| e.to_string())
}

pub fn acme_valid_label() -> ConfidentialityLabel {
    ConfidentialityLabel::new(LabelPolicy::new("ACME"), ClassificationLevel::Internal)
        .with_category(CategoryMarking {
            tag_name: "Sensitive".to_owned(),
            category_type: mim_labeling::CategoryType::Restrictive,
            values: vec!["RED".to_owned()],
        })
}

pub fn acme_invalid_label() -> ConfidentialityLabel {
    ConfidentialityLabel::new(LabelPolicy::new("ACME"), ClassificationLevel::Confidential)
        .with_category(CategoryMarking {
            tag_name: "Sensitive".to_owned(),
            category_type: mim_labeling::CategoryType::Restrictive,
            values: vec!["RED".to_owned()],
        })
}
