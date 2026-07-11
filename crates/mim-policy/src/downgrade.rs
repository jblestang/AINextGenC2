//! Category-aware cross-domain downgrade rules.

use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelResult, SecurityDomain};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DowngradeConfig {
    #[serde(default = "default_true")]
    pub intersect_releasability: bool,
    #[serde(default = "default_true")]
    pub strip_non_target_categories: bool,
}

fn default_true() -> bool {
    true
}

impl Default for DowngradeConfig {
    fn default() -> Self {
        Self {
            intersect_releasability: true,
            strip_non_target_categories: true,
        }
    }
}

/// Compute an effective label for release into `target`, applying downgrade rules.
pub fn downgraded_label_for_target(
    label: &ConfidentialityLabel,
    target: &SecurityDomain,
    config: &DowngradeConfig,
) -> LabelResult<ConfidentialityLabel> {
    let mut effective = label.clone();
    if effective.classification > target.max_classification {
        effective.classification = target.max_classification;
    }
    if config.intersect_releasability {
        for category in &mut effective.categories {
            if category.tag_name.eq_ignore_ascii_case("Releasable to") {
                category
                    .values
                    .retain(|country| target.accepts_country(country));
            }
        }
        if config.strip_non_target_categories {
            effective.categories.retain(|category| {
                if category.tag_name.eq_ignore_ascii_case("Releasable to") {
                    !category.values.is_empty()
                } else {
                    true
                }
            });
        }
    }
    effective.validate()?;
    Ok(effective)
}

/// Returns true when label exceeds target domain and requires downgrade rather than deny.
pub fn requires_downgrade(label: &ConfidentialityLabel, target: &SecurityDomain) -> bool {
    label.classification > target.max_classification
        && target.max_classification >= ClassificationLevel::Unclassified
}
