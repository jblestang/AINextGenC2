use mim_core::{MimUri, RepresentationMetadata, RepresentationTerm, SemanticId};
use serde::{Deserialize, Serialize};

use crate::codelist::CodeList;
use crate::taxonomy::TaxonomyNode;

/// Kind of element in a MIM manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ModelElementKind {
    Class,
    DataType,
    Enumeration,
    Attribute,
    Association,
    Package,
}

/// Specification for a single MIM model element.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelElementSpec {
    pub name: String,
    pub kind: ModelElementKind,
    pub semantic_id: SemanticId,
    pub uri: MimUri,
    pub package_path: String,
    pub definition: String,
    pub parent_class: Option<String>,
    pub representation_term: Option<RepresentationTerm>,
    pub representation_metadata: Option<RepresentationMetadata>,
    pub multiplicity_lower: Option<u32>,
    pub multiplicity_upper: Option<String>,
    pub is_mandatory: bool,
    pub is_nillable: bool,
}

/// Portable MIM model manifest (JSON) for loading full model definitions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MimManifest {
    pub version: String,
    pub release_date: String,
    pub description: String,
    pub expected_object_types: u32,
    pub expected_action_types: u32,
    pub expected_code_lists: u32,
    pub taxonomy: Vec<TaxonomyNode>,
    pub elements: Vec<ModelElementSpec>,
    pub code_lists: Vec<CodeList>,
}

impl MimManifest {
    pub fn from_json(data: &str) -> Result<Self, mim_core::MimError> {
        let manifest: Self = serde_json::from_str(data)?;
        manifest.validate_structure()?;
        Ok(manifest)
    }

    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self, mim_core::MimError> {
        let manifest: Self = serde_json::from_reader(reader)?;
        manifest.validate_structure()?;
        Ok(manifest)
    }

    fn validate_structure(&self) -> Result<(), mim_core::MimError> {
        if self.version.is_empty() {
            return Err(mim_core::MimError::Model(
                "manifest version must not be empty".into(),
            ));
        }
        if self.taxonomy.is_empty() {
            return Err(mim_core::MimError::Model(
                "manifest taxonomy must not be empty".into(),
            ));
        }
        if self.elements.is_empty() {
            return Err(mim_core::MimError::Model(
                "manifest must contain at least one element".into(),
            ));
        }
        Ok(())
    }

    pub fn coverage_ratio(&self) -> (f64, f64, f64) {
        let object_count = self
            .taxonomy
            .iter()
            .filter(|node| node.is_object())
            .count() as f64;
        let action_count = self
            .taxonomy
            .iter()
            .filter(|node| node.is_action())
            .count() as f64;
        let code_list_count = self.code_lists.len() as f64;

        let object_ratio = if self.expected_object_types == 0 {
            1.0
        } else {
            object_count / self.expected_object_types as f64
        };
        let action_ratio = if self.expected_action_types == 0 {
            1.0
        } else {
            action_count / self.expected_action_types as f64
        };
        let code_list_ratio = if self.expected_code_lists == 0 {
            1.0
        } else {
            code_list_count / self.expected_code_lists as f64
        };

        (object_ratio, action_ratio, code_list_ratio)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_manifest() {
        let json = r#"{
            "version": "5.1.0",
            "releaseDate": "2020-09-28",
            "description": "test",
            "expectedObjectTypes": 2300,
            "expectedActionTypes": 500,
            "expectedCodeLists": 400,
            "taxonomy": [],
            "elements": [],
            "codeLists": []
        }"#;
        let err = MimManifest::from_json(json).expect_err("must fail");
        assert!(matches!(err, mim_core::MimError::Model(_)));
    }
}
