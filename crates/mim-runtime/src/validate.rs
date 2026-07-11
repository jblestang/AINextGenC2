use mim_core::{MimError, MimResult, Nillable};
use mim_model::ModelRegistry;
use serde_json::Value;

use crate::instance::{InstanceStore, MimInstance};

/// Severity of a validation issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationSeverity {
    Error,
    Warning,
}

/// Single validation finding.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidationIssue {
    pub severity: ValidationSeverity,
    pub instance_oid: Option<String>,
    pub property: Option<String>,
    pub message: String,
}

/// Aggregated validation report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ValidationReport {
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        !self
            .issues
            .iter()
            .any(|issue| issue.severity == ValidationSeverity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|issue| issue.severity == ValidationSeverity::Error)
            .count()
    }

    pub fn push_error(
        &mut self,
        instance_oid: Option<String>,
        property: Option<String>,
        message: impl Into<String>,
    ) {
        self.issues.push(ValidationIssue {
            severity: ValidationSeverity::Error,
            instance_oid,
            property,
            message: message.into(),
        });
    }
}

/// MIM instance validator against a loaded model registry.
pub struct Validator<'a> {
    registry: &'a ModelRegistry,
}

impl<'a> Validator<'a> {
    pub fn new(registry: &'a ModelRegistry) -> Self {
        Self { registry }
    }

    pub fn validate_instance(&self, instance: &MimInstance) -> ValidationReport {
        let mut report = ValidationReport::default();
        let oid = Some(instance.oid.to_string());

        if self.registry.element_by_name(&instance.class_name).is_none()
            && self.registry.taxonomy_node(&instance.class_name).is_none()
        {
            report.push_error(
                oid.clone(),
                None,
                format!("unknown class '{}'", instance.class_name),
            );
            return report;
        }

        for property in &instance.properties {
            self.validate_property(&mut report, oid.clone(), property);
        }

        self.validate_required_attributes(&mut report, oid.clone(), instance);

        report
    }

    pub fn validate_store(&self, store: &InstanceStore) -> ValidationReport {
        let mut report = ValidationReport::default();
        for instance in store.instances() {
            let instance_report = self.validate_instance(instance);
            report.issues.extend(instance_report.issues);
        }
        report
    }

    fn validate_property(
        &self,
        report: &mut ValidationReport,
        oid: Option<String>,
        property: &crate::instance::PropertyValue,
    ) {
        match &property.value {
            Nillable::Value { value } => {
                if let Some(code_list) = self.registry.code_list_for_attribute(&property.name) {
                    if let Some(code) = value_as_string(value) {
                        if let Err(message) = code_list.validate_value(&code) {
                            report.push_error(oid.clone(), Some(property.name.clone()), message);
                        }
                    }
                }
            }
            Nillable::Nil { .. } => {}
            Nillable::Absent => {}
        }
    }

    fn validate_required_attributes(
        &self,
        report: &mut ValidationReport,
        oid: Option<String>,
        instance: &MimInstance,
    ) {
        let mut classes = vec![instance.class_name.clone()];
        classes.extend(self.registry.ancestors_of(&instance.class_name));

        for class_name in classes {
            for attribute in self.registry.attributes_for_class(&class_name) {
                if !attribute.is_mandatory {
                    continue;
                }

                let present = instance
                    .property(&attribute.name)
                    .map(|property| !matches!(property.value, Nillable::Absent))
                    .unwrap_or(false);

                if !present {
                    report.push_error(
                        oid.clone(),
                        Some(attribute.name.clone()),
                        format!(
                            "mandatory attribute '{}' on class '{}' is absent",
                            attribute.name, class_name
                        ),
                    );
                }
            }
        }
    }
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map
            .get("codeValue")
            .or_else(|| map.get("value"))
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        _ => None,
    }
}

pub fn validate_json_instance(
    registry: &ModelRegistry,
    json: &str,
) -> MimResult<ValidationReport> {
    let instance: MimInstance =
        serde_json::from_str(json).map_err(|e| MimError::Parse(e.to_string()))?;
    let validator = Validator::new(registry);
    Ok(validator.validate_instance(&instance))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::instance::PropertyValue;
    use mim_core::{MimUri, SemanticId};
    use mim_model::manifest::{MimManifest, ModelElementKind, ModelElementSpec};
    use mim_model::{CodeList, CodeValue, ModelRegistry, TaxonomyNode};

    fn registry_with_unit_range_code() -> ModelRegistry {
        let manifest = MimManifest {
            version: "5.1.0".into(),
            release_date: "2020-09-28".into(),
            description: "test".into(),
            expected_object_types: 1,
            expected_action_types: 0,
            expected_code_lists: 1,
            taxonomy: vec![
                TaxonomyNode {
                    name: "Object".into(),
                    semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                        .expect("id"),
                    parent: None,
                    object_kind: None,
                    action_kind: None,
                    definition: "Root".into(),
                    package_path: "Classifiers::Object".into(),
                },
                TaxonomyNode {
                    name: "Unit".into(),
                    semantic_id: SemanticId::parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
                        .expect("id"),
                    parent: Some("Object".into()),
                    object_kind: Some(mim_model::ObjectKind::Organisation),
                    action_kind: None,
                    definition: "Military unit".into(),
                    package_path: "Classifiers::Object::Organisation::Unit".into(),
                },
            ],
            elements: vec![
                ModelElementSpec {
                    name: "Unit".into(),
                    kind: ModelElementKind::Class,
                    semantic_id: SemanticId::parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
                        .expect("id"),
                    uri: MimUri::parse(
                        "https://www.mimworld.org/mim/5.1.0/Classifiers/Object/Organisation/Unit",
                    )
                    .expect("uri"),
                    package_path: "Classifiers::Object::Organisation::Unit".into(),
                    definition: "Military unit".into(),
                    parent_class: Some("Object".into()),
                    representation_term: None,
                    representation_metadata: None,
                    multiplicity_lower: None,
                    multiplicity_upper: None,
                    is_mandatory: false,
                    is_nillable: true,
                },
                ModelElementSpec {
                    name: "unitRangeCode".into(),
                    kind: ModelElementKind::Attribute,
                    semantic_id: SemanticId::parse("cccccccc-cccc-4ccc-8ccc-cccccccccccd")
                        .expect("id"),
                    uri: MimUri::parse(
                        "https://www.mimworld.org/mim/5.1.0/Classifiers/Object/Organisation/Unit/unitRangeCode",
                    )
                    .expect("uri"),
                    package_path: "Classifiers::Object::Organisation::Unit".into(),
                    definition: "Unit range".into(),
                    parent_class: Some("Unit".into()),
                    representation_term: Some(mim_core::RepresentationTerm::Code),
                    representation_metadata: None,
                    multiplicity_lower: Some(0),
                    multiplicity_upper: Some("1".into()),
                    is_mandatory: false,
                    is_nillable: true,
                },
            ],
            code_lists: vec![CodeList {
                name: "UnitRangeCode".into(),
                semantic_id: SemanticId::parse("080de7fa-fc13-4201-8364-0aa47e5c10bc")
                    .expect("id"),
                complete: true,
                managed: false,
                ordered: true,
                definition: None,
                values: vec![CodeValue {
                    name: "CloseRange".into(),
                    semantic_id: SemanticId::parse("11111111-1111-4111-8111-111111111111")
                        .expect("id"),
                    definition: None,
                    order: Some(1),
                    lower_than: vec![],
                }],
            }],
        };
        ModelRegistry::from_manifest(manifest).expect("registry")
    }

    #[test]
    fn rejects_invalid_complete_code_value() {
        let registry = registry_with_unit_range_code();
        let validator = Validator::new(&registry);
        let class_id =
            SemanticId::parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("id");
        let instance = MimInstance::new("Unit", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("unitRangeCode", "InvalidValue"));

        let report = validator.validate_instance(&instance);
        assert!(!report.is_valid());
        assert_eq!(report.error_count(), 1);
    }
}
