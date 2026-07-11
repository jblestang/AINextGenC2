use chrono::{DateTime, Utc};
use mim_model::SecurityClassification;
use serde::{Deserialize, Serialize};

use crate::classification::ClassificationLevel;
use crate::error::{LabelError, LabelResult};
use crate::policy::LabelPolicy;

/// STANAG 4774 category type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CategoryType {
    Restrictive,
    Permissive,
    Informative,
}

/// A category marking such as releasability or handling caveat.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryMarking {
    pub tag_name: String,
    pub category_type: CategoryType,
    pub values: Vec<String>,
}

impl CategoryMarking {
    pub fn releasable_to(countries: Vec<String>) -> Self {
        Self {
            tag_name: "Releasable to".to_owned(),
            category_type: CategoryType::Permissive,
            values: countries,
        }
    }

    pub fn handling_caveat(caveat: impl Into<String>) -> Self {
        Self {
            tag_name: "Handling".to_owned(),
            category_type: CategoryType::Restrictive,
            values: vec![caveat.into()],
        }
    }
}

/// Canonical confidentiality label used across STANAG 4774/4778 and ZTDF.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfidentialityLabel {
    pub policy: LabelPolicy,
    pub classification: ClassificationLevel,
    pub privacy_mark: Option<String>,
    pub colour: Option<String>,
    pub marking_data: Option<String>,
    pub categories: Vec<CategoryMarking>,
    pub alternative_labels: Vec<ConfidentialityLabel>,
    pub creation_time: Option<DateTime<Utc>>,
    pub review_date_time: Option<DateTime<Utc>>,
}

impl ConfidentialityLabel {
    pub fn new(policy: LabelPolicy, classification: ClassificationLevel) -> Self {
        Self {
            policy,
            classification,
            privacy_mark: None,
            colour: None,
            marking_data: None,
            categories: Vec::new(),
            alternative_labels: Vec::new(),
            creation_time: None,
            review_date_time: None,
        }
    }

    pub fn with_colour(mut self, colour: impl Into<String>) -> Self {
        self.colour = Some(colour.into());
        self
    }

    pub fn with_marking_data(mut self, data: impl Into<String>) -> Self {
        self.marking_data = Some(data.into());
        self
    }

    pub fn with_alternative_label(mut self, label: ConfidentialityLabel) -> Self {
        self.alternative_labels.push(label);
        self
    }

    pub fn with_category(mut self, category: CategoryMarking) -> Self {
        self.categories.push(category);
        self
    }

    pub fn with_creation_time(mut self, time: DateTime<Utc>) -> Self {
        self.creation_time = Some(time);
        self
    }

    pub fn with_review_date_time(mut self, time: DateTime<Utc>) -> Self {
        self.review_date_time = Some(time);
        self
    }

    pub fn validate(&self) -> LabelResult<()> {
        if self.policy.identifier.is_empty() {
            return Err(LabelError::Validation(
                "policy identifier is mandatory".into(),
            ));
        }
        if !self.policy.allows_classification(self.classification) {
            return Err(LabelError::Validation(format!(
                "classification {} not allowed by policy {}",
                self.classification.as_stanag_str(),
                self.policy.identifier
            )));
        }
        for category in &self.categories {
            if category.tag_name.is_empty() {
                return Err(LabelError::Validation(
                    "category tagName must not be empty".into(),
                ));
            }
            if category.values.is_empty() {
                return Err(LabelError::Validation(format!(
                    "category '{}' requires at least one value",
                    category.tag_name
                )));
            }
        }
        Ok(())
    }

    pub fn releasable_countries(&self) -> Vec<String> {
        self.categories
            .iter()
            .filter(|c| c.tag_name.eq_ignore_ascii_case("Releasable to"))
            .flat_map(|c| c.values.clone())
            .collect()
    }

    pub fn from_mim_security(security: &SecurityClassification) -> LabelResult<Self> {
        let policy_id = security
            .policy
            .as_option()
            .map(|s| s.as_str())
            .unwrap_or("NATO");
        let policy = LabelPolicy::nato().with_identifier(policy_id);

        let classification_str = security
            .classification
            .as_option()
            .map(|s| s.as_str())
            .unwrap_or("UNCLASSIFIED");
        let classification = ClassificationLevel::parse(classification_str)?;

        let mut label = Self::new(policy, classification);

        if let Some(releasability) = security.releasability.as_option() {
            let countries: Vec<String> = releasability
                .split([',', ';', ' '])
                .filter(|s| !s.is_empty())
                .map(str::to_uppercase)
                .collect();
            if !countries.is_empty() {
                label = label.with_category(CategoryMarking::releasable_to(countries));
            }
        }

        Ok(label)
    }

    pub fn to_mim_security(&self) -> SecurityClassification {
        use mim_core::Nillable;

        let releasability = self.releasable_countries().join(",");
        SecurityClassification {
            policy: Nillable::value(self.policy.identifier.clone()),
            classification: Nillable::value(self.classification.as_stanag_str().to_owned()),
            releasability: if releasability.is_empty() {
                Nillable::Absent
            } else {
                Nillable::value(releasability)
            },
        }
    }
}
