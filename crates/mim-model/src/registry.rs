use indexmap::IndexMap;
use mim_core::{MimError, MimResult, SemanticId};

use crate::codelist::CodeList;
use crate::manifest::{MimManifest, ModelElementSpec};
use crate::taxonomy::{ActionKind, ObjectKind, TaxonomyNode};

/// In-memory registry of MIM model elements for runtime resolution.
#[derive(Clone, Debug, Default)]
pub struct ModelRegistry {
    version: String,
    elements_by_name: IndexMap<String, ModelElementSpec>,
    elements_by_semantic_id: IndexMap<SemanticId, ModelElementSpec>,
    taxonomy_by_name: IndexMap<String, TaxonomyNode>,
    code_lists_by_name: IndexMap<String, CodeList>,
    object_kinds: Vec<ObjectKind>,
    action_kinds: Vec<ActionKind>,
}

impl ModelRegistry {
    pub fn from_manifest(manifest: MimManifest) -> MimResult<Self> {
        let mut registry = Self {
            version: manifest.version.clone(),
            object_kinds: ObjectKind::ALL.to_vec(),
            action_kinds: ActionKind::ALL.to_vec(),
            ..Default::default()
        };

        for node in manifest.taxonomy {
            registry.taxonomy_by_name.insert(node.name.clone(), node);
        }

        for element in manifest.elements {
            registry
                .elements_by_semantic_id
                .insert(element.semantic_id, element.clone());
            registry.elements_by_name.insert(element.name.clone(), element);
        }

        for code_list in manifest.code_lists {
            registry
                .code_lists_by_name
                .insert(code_list.name.clone(), code_list);
        }

        registry.validate_integrity()?;
        Ok(registry)
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn element_by_name(&self, name: &str) -> Option<&ModelElementSpec> {
        self.elements_by_name.get(name)
    }

    pub fn element_by_semantic_id(&self, id: SemanticId) -> Option<&ModelElementSpec> {
        self.elements_by_semantic_id.get(&id)
    }

    pub fn taxonomy_node(&self, name: &str) -> Option<&TaxonomyNode> {
        self.taxonomy_by_name.get(name)
    }

    pub fn code_list(&self, name: &str) -> Option<&CodeList> {
        self.code_lists_by_name.get(name)
    }

    pub fn object_type_count(&self) -> usize {
        self.taxonomy_by_name
            .values()
            .filter(|node| node.is_object())
            .count()
    }

    pub fn action_type_count(&self) -> usize {
        self.taxonomy_by_name
            .values()
            .filter(|node| node.is_action())
            .count()
    }

    pub fn code_list_count(&self) -> usize {
        self.code_lists_by_name.len()
    }

    pub fn element_count(&self) -> usize {
        self.elements_by_name.len()
    }

    pub fn supports_object_kind(&self, kind: ObjectKind) -> bool {
        self.object_kinds.contains(&kind)
    }

    pub fn supports_action_kind(&self, kind: ActionKind) -> bool {
        self.action_kinds.contains(&kind)
    }

    pub fn attributes_for_class(&self, class_name: &str) -> Vec<&ModelElementSpec> {
        self.elements_by_name
            .values()
            .filter(|element| {
                element.kind == crate::manifest::ModelElementKind::Attribute
                    && element.parent_class.as_deref() == Some(class_name)
            })
            .collect()
    }

    pub fn ancestors_of(&self, class_name: &str) -> Vec<String> {
        let mut ancestors = Vec::new();
        let mut current = self
            .element_by_name(class_name)
            .and_then(|element| element.parent_class.clone())
            .or_else(|| {
                self.taxonomy_node(class_name)
                    .and_then(|node| node.parent.clone())
            });

        while let Some(parent) = current {
            ancestors.push(parent.clone());
            current = self
                .element_by_name(&parent)
                .and_then(|element| element.parent_class.clone())
                .or_else(|| {
                    self.taxonomy_node(&parent)
                        .and_then(|node| node.parent.clone())
                });
        }

        ancestors
    }

    pub fn code_list_for_attribute(&self, attribute_name: &str) -> Option<&CodeList> {
        let element = self.element_by_name(attribute_name)?;
        if element.representation_term != Some(mim_core::RepresentationTerm::Code) {
            return None;
        }
        property_to_code_list_name(attribute_name)
            .and_then(|name| self.code_lists_by_name.get(&name))
    }

    fn validate_integrity(&self) -> MimResult<()> {
        for node in self.taxonomy_by_name.values() {
            if let Some(parent) = &node.parent {
                if !self.taxonomy_by_name.contains_key(parent) {
                    return Err(MimError::Model(format!(
                        "taxonomy node '{}' references unknown parent '{}'",
                        node.name, parent
                    )));
                }
            }
        }

        for element in self.elements_by_name.values() {
            if let Some(parent) = &element.parent_class {
                if !self.elements_by_name.contains_key(parent)
                    && !self.taxonomy_by_name.contains_key(parent)
                {
                    return Err(MimError::Model(format!(
                        "element '{}' references unknown parent class '{}'",
                        element.name, parent
                    )));
                }
            }
        }

        Ok(())
    }
}

fn property_to_code_list_name(property_name: &str) -> Option<String> {
    if !property_name.ends_with("Code") {
        return None;
    }
    let mut chars = property_name.chars();
    let first = chars.next()?;
    let rest: String = chars.collect();
    Some(format!("{}{}", first.to_ascii_uppercase(), rest))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::manifest::ModelElementKind;
    use mim_core::MimUri;

    fn minimal_manifest() -> MimManifest {
        MimManifest {
            version: "5.1.0".into(),
            release_date: "2020-09-28".into(),
            description: "minimal".into(),
            expected_object_types: 2300,
            expected_action_types: 500,
            expected_code_lists: 400,
            taxonomy: vec![TaxonomyNode {
                name: "Object".into(),
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
                parent: None,
                object_kind: None,
                action_kind: None,
                definition: "Root object".into(),
                package_path: "Classifiers::Object".into(),
            }],
            elements: vec![ModelElementSpec {
                name: "Object".into(),
                kind: ModelElementKind::Class,
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
                uri: MimUri::parse("https://www.mimworld.org/mim/5.1.0/Classifiers/Object")
                    .expect("uri"),
                package_path: "Classifiers::Object".into(),
                definition: "Root object".into(),
                parent_class: None,
                representation_term: None,
                representation_metadata: None,
                multiplicity_lower: None,
                multiplicity_upper: None,
                is_mandatory: false,
                is_nillable: true,
            }],
            code_lists: vec![],
        }
    }

    #[test]
    fn builds_registry_from_manifest() {
        let registry = ModelRegistry::from_manifest(minimal_manifest()).expect("registry");
        assert_eq!(registry.version(), "5.1.0");
        assert_eq!(registry.element_count(), 1);
    }
}
