//! XML-SPIF policy document model (ADatP-4774.1 / ISO 29008).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpifVersionInfo {
    pub spif_version: Option<String>,
    pub issuing_authority: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpifPolicy {
    pub policy_id: String,
    pub policy_oid: Option<String>,
    pub version_info: Option<SpifVersionInfo>,
    pub allowed_classifications: Vec<String>,
    pub categories: Vec<SpifCategory>,
    pub validations: Vec<SpifValidation>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpifCategory {
    pub name: String,
    pub category_type: SpifCategoryType,
    pub allowed_values: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpifCategoryType {
    Restrictive,
    Permissive,
    Informative,
}

/// SPIF validation rule: when classification matches, require category values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpifValidation {
    pub classification: String,
    pub category_name: String,
    pub required_any_of: Vec<String>,
}

impl SpifPolicy {
    pub fn acme() -> Self {
        Self {
            policy_id: "ACME".into(),
            policy_oid: None,
            version_info: None,
            allowed_classifications: vec![
                "PUBLIC".into(),
                "INTERNAL".into(),
                "CONFIDENTIAL".into(),
            ],
            categories: vec![
                SpifCategory {
                    name: "Sensitive".into(),
                    category_type: SpifCategoryType::Restrictive,
                    allowed_values: vec!["RED".into(), "AMBER".into(), "GREEN".into()],
                },
                SpifCategory {
                    name: "Releasable To".into(),
                    category_type: SpifCategoryType::Permissive,
                    allowed_values: vec![
                        "MOCK".into(),
                        "PHONY".into(),
                        "ACME".into(),
                    ],
                },
            ],
            validations: vec![SpifValidation {
                classification: "CONFIDENTIAL".into(),
                category_name: "Releasable To".into(),
                required_any_of: vec!["MOCK".into(), "PHONY".into()],
            }],
        }
    }

    pub fn nato() -> Self {
        Self {
            policy_id: "NATO".into(),
            policy_oid: Some(
                "urn:oid:2.16.840.1.101.2.3.6.1.31778.102.25".into(),
            ),
            version_info: None,
            allowed_classifications: vec![
                "UNCLASSIFIED".into(),
                "NATO UNCLASSIFIED".into(),
                "RESTRICTED".into(),
                "NATO RESTRICTED".into(),
                "CONFIDENTIAL".into(),
                "NATO CONFIDENTIAL".into(),
                "NATO/EAPC CONFIDENTIAL".into(),
                "NATO/KFOR CONFIDENTIAL".into(),
                "SECRET".into(),
                "NATO SECRET".into(),
                "COSMIC TOP SECRET".into(),
            ],
            categories: vec![SpifCategory {
                name: "Releasable to".into(),
                category_type: SpifCategoryType::Permissive,
                allowed_values: vec![
                    "USA".into(),
                    "GBR".into(),
                    "DEU".into(),
                    "FRA".into(),
                ],
            }],
            validations: vec![],
        }
    }

    pub fn capco_us() -> Self {
        Self {
            policy_id: "US".into(),
            policy_oid: Some("2.16.840.1.101.2.3.48.2.1".into()),
            version_info: None,
            allowed_classifications: vec![
                "UNCLASSIFIED".into(),
                "CONFIDENTIAL".into(),
                "SECRET".into(),
                "TOP SECRET".into(),
            ],
            categories: vec![
                SpifCategory {
                    name: "SCI".into(),
                    category_type: SpifCategoryType::Restrictive,
                    allowed_values: vec!["SI".into(), "TK".into(), "HCS".into()],
                },
                SpifCategory {
                    name: "Releasable To".into(),
                    category_type: SpifCategoryType::Permissive,
                    allowed_values: vec![
                        "USA".into(),
                        "FVEY".into(),
                        "NATO".into(),
                    ],
                },
            ],
            validations: vec![SpifValidation {
                classification: "TOP SECRET".into(),
                category_name: "SCI".into(),
                required_any_of: vec!["SI".into(), "TK".into()],
            }],
        }
    }

    pub fn uk_demo() -> Self {
        Self {
            policy_id: "DEMO-UK".into(),
            policy_oid: Some("1.2.826.0.1.6726289.0.2".into()),
            version_info: None,
            allowed_classifications: vec![
                "OFFICIAL".into(),
                "OFFICIAL-SENSITIVE".into(),
                "SECRET".into(),
                "TOP SECRET".into(),
            ],
            categories: vec![
                SpifCategory {
                    name: "Handling".into(),
                    category_type: SpifCategoryType::Restrictive,
                    allowed_values: vec!["LOCSEN".into(), "UK EYES ONLY".into()],
                },
                SpifCategory {
                    name: "Releasable To".into(),
                    category_type: SpifCategoryType::Permissive,
                    allowed_values: vec![
                        "UK".into(),
                        "NATO".into(),
                        "EU".into(),
                    ],
                },
            ],
            validations: vec![SpifValidation {
                classification: "SECRET".into(),
                category_name: "Handling".into(),
                required_any_of: vec!["LOCSEN".into()],
            }],
        }
    }
}
