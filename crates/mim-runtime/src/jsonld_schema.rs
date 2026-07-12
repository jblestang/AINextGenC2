use serde_json::Value;

use crate::instance_schema::validate_instance_json_schema;
use crate::serialize::MIM_JSONLD_CONTEXT;

/// Structural validation for MIP4-IES JSON-LD instance documents on the wire.
pub fn validate_instance_jsonld(value: &Value) -> Result<(), String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "JSON-LD root must be a JSON object".to_string())?;

    let context = obj
        .get("@context")
        .ok_or_else(|| "JSON-LD missing @context".to_string())?;
    validate_jsonld_context(context)?;

    require_string_field(obj, "@id")?;

    let has_semantic_id = obj.contains_key("mim:semanticId") || obj.contains_key("semanticId");
    if !has_semantic_id {
        return Err("JSON-LD missing mim:semanticId".to_string());
    }

    let data = obj
        .get("mim:data")
        .ok_or_else(|| "JSON-LD missing mim:data".to_string())?;
    validate_instance_json_schema(data)
}

pub fn validate_instance_jsonld_str(json: &str) -> Result<(), String> {
    let value: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    validate_instance_jsonld(&value)
}

fn validate_jsonld_context(context: &Value) -> Result<(), String> {
    match context {
        Value::String(url) if url == MIM_JSONLD_CONTEXT || url.contains("mimworld.org") => Ok(()),
        Value::Object(map) if map.contains_key("mim") || map.contains_key("@context") => Ok(()),
        Value::String(url) => Err(format!("unexpected JSON-LD @context URL: {url}")),
        _ => Err("JSON-LD @context must be a URL string or context object".to_string()),
    }
}

fn require_string_field(obj: &serde_json::Map<String, Value>, key: &str) -> Result<(), String> {
    match obj.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(()),
        Some(_) => Err(format!("field '{key}' must be a non-empty string")),
        None => Err(format!("missing required field '{key}'")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::SemanticId;

    use super::*;
    use crate::instance::{MimInstance, PropertyValue};
    use crate::serialize::{SerializationFormat, Serializer};
    use mim_model::ModelRegistry;

    fn test_registry() -> ModelRegistry {
        use mim_core::MimUri;
        use mim_model::manifest::{ModelElementKind, ModelElementSpec};
        use mim_model::TaxonomyNode;

        ModelRegistry::from_manifest(mim_model::MimManifest {
            version: "5.1.0".into(),
            release_date: "2020-09-28".into(),
            description: "minimal".into(),
            expected_object_types: 1,
            expected_action_types: 0,
            expected_code_lists: 0,
            taxonomy: vec![TaxonomyNode {
                name: "Target".into(),
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id"),
                parent: None,
                object_kind: Some(mim_model::ObjectKind::InformationResource),
                action_kind: None,
                definition: "Target".into(),
                package_path: "Classifiers::Object::InformationResource::Target".into(),
            }],
            elements: vec![ModelElementSpec {
                name: "Target".into(),
                kind: ModelElementKind::Class,
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id"),
                uri: MimUri::parse(
                    "https://www.mimworld.org/mim/5.1.0/Classifiers/Object/InformationResource/Target",
                )
                .expect("uri"),
                package_path: "Classifiers::Object::InformationResource::Target".into(),
                definition: "Target".into(),
                parent_class: None,
                representation_term: None,
                representation_metadata: None,
                multiplicity_lower: None,
                multiplicity_upper: None,
                is_mandatory: false,
                is_nillable: true,
            }],
            code_lists: vec![],
        })
        .expect("registry")
    }

    #[test]
    fn accepts_serialized_jsonld_instance() {
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        let instance = MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "HOSTILE-1"));
        let jsonld = Serializer::new(test_registry())
            .serialize_instance(&instance, SerializationFormat::JsonLd)
            .expect("jsonld");
        validate_instance_jsonld_str(&jsonld).expect("valid");
    }

    #[test]
    fn rejects_missing_data_wrapper() {
        let bad = serde_json::json!({
            "@context": MIM_JSONLD_CONTEXT,
            "@id": "urn:uuid:test",
            "mim:semanticId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        });
        assert!(validate_instance_jsonld(&bad).is_err());
    }
}
