use mim_labeling::{CategoryMarking, ClassificationLevel, ConfidentialityLabel, LabelPolicy};

/// ADatP-4774.1 ACME SPIF semantic validation (Figures 7 and 9).
pub fn validate_acme_semantics(label: &ConfidentialityLabel) -> Result<(), String> {
    if label.policy.identifier != "ACME" {
        return Err(format!(
            "invalid policy identifier, expected ACME, got {}",
            label.policy.identifier
        ));
    }

    let allowed = ["PUBLIC", "CONFIDENTIAL", "INTERNAL"];
    let class = label.classification.as_stanag_str();
    if !allowed.contains(&class) {
        return Err(format!(
            "invalid classification, expected PUBLIC, CONFIDENTIAL or INTERNAL, got {class}"
        ));
    }

    if label.classification == ClassificationLevel::Confidential {
        let releasable = label
            .categories
            .iter()
            .find(|c| c.tag_name.eq_ignore_ascii_case("Releasable To"))
            .map(|c| c.values.clone())
            .unwrap_or_default();
        let has_mock = releasable.iter().any(|v| v == "MOCK");
        let has_phony = releasable.iter().any(|v| v == "PHONY");
        if !has_mock && !has_phony {
            return Err(
                "None of the required categories for classification CONFIDENTIAL are present"
                    .into(),
            );
        }
    }

    Ok(())
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
