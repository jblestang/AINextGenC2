use mim_core::SemanticId;
use serde::{Deserialize, Serialize};

/// MIM code list semantics (complete, managed, ordered).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CodeListKind {
    Complete,
    Extensible,
    Managed,
    Ordered,
}

/// A single code value within a MIM enumeration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeValue {
    pub name: String,
    pub semantic_id: SemanticId,
    pub definition: Option<String>,
    pub order: Option<u32>,
    pub lower_than: Vec<String>,
}

/// MIM code list (UML enumeration) with tagged values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeList {
    pub name: String,
    pub semantic_id: SemanticId,
    pub complete: bool,
    pub managed: bool,
    pub ordered: bool,
    pub definition: Option<String>,
    pub values: Vec<CodeValue>,
}

impl CodeList {
    pub fn kinds(&self) -> Vec<CodeListKind> {
        let mut kinds = Vec::new();
        if self.complete {
            kinds.push(CodeListKind::Complete);
        } else {
            kinds.push(CodeListKind::Extensible);
        }
        if self.managed {
            kinds.push(CodeListKind::Managed);
        }
        if self.ordered {
            kinds.push(CodeListKind::Ordered);
        }
        kinds
    }

    pub fn contains_value(&self, name: &str) -> bool {
        self.values.iter().any(|v| v.name == name)
    }

    pub fn validate_value(&self, name: &str) -> Result<(), String> {
        if self.contains_value(name) {
            return Ok(());
        }
        if self.complete {
            return Err(format!(
                "code value '{name}' is not in complete code list '{}'",
                self.name
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn unit_range_code_list() -> CodeList {
        CodeList {
            name: "UnitRangeCode".into(),
            semantic_id: SemanticId::parse("080de7fa-fc13-4201-8364-0aa47e5c10bc").expect("id"),
            complete: true,
            managed: false,
            ordered: true,
            definition: Some(
                "The indication of the maximum distance at which a Unit can operate under normal conditions.".into(),
            ),
            values: vec![
                CodeValue {
                    name: "CloseRange".into(),
                    semantic_id: SemanticId::parse("11111111-1111-4111-8111-111111111111")
                        .expect("id"),
                    definition: None,
                    order: Some(1),
                    lower_than: vec!["ShortRange".into()],
                },
                CodeValue {
                    name: "ShortRange".into(),
                    semantic_id: SemanticId::parse("22222222-2222-4222-8222-222222222222")
                        .expect("id"),
                    definition: None,
                    order: Some(2),
                    lower_than: vec!["MediumRange".into()],
                },
                CodeValue {
                    name: "MediumRange".into(),
                    semantic_id: SemanticId::parse("33333333-3333-4333-8333-333333333333")
                        .expect("id"),
                    definition: None,
                    order: Some(3),
                    lower_than: vec!["LongRange".into()],
                },
                CodeValue {
                    name: "LongRange".into(),
                    semantic_id: SemanticId::parse("44444444-4444-4444-8444-444444444444")
                        .expect("id"),
                    definition: None,
                    order: Some(4),
                    lower_than: vec![],
                },
            ],
        }
    }

    #[test]
    fn complete_codelist_rejects_unknown_values() {
        let list = unit_range_code_list();
        assert!(list.validate_value("CloseRange").is_ok());
        assert!(list.validate_value("Other").is_err());
    }

    #[test]
    fn ordered_codelist_kinds() {
        let list = unit_range_code_list();
        assert!(list.kinds().contains(&CodeListKind::Complete));
        assert!(list.kinds().contains(&CodeListKind::Ordered));
    }
}
