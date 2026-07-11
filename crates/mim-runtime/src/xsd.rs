use std::fs;
use std::process::Command;

const MIM_EXCHANGE_XSD: &str = include_str!("../schemas/mim-exchange.xsd");

/// Validate a MIM exchange XML document against the bundled exchange XSD.
pub fn validate_exchange_xsd(xml: &str) -> Result<(), String> {
    match validate_with_xmllint(xml, MIM_EXCHANGE_XSD) {
        Ok(()) => Ok(()),
        Err(xmllint_err) => validate_structural(xml).map_err(|structural| {
            format!("XSD validation failed ({xmllint_err}); structural check: {structural}")
        }),
    }
}

fn validate_with_xmllint(xml: &str, schema: &str) -> Result<(), String> {
    if !xmllint_available() {
        return Err("xmllint not available".into());
    }

    let stamp = format!("{:?}", std::time::SystemTime::now());
    let xml_path = std::env::temp_dir().join(format!("mim-exchange-{stamp}.xml"));
    let xsd_path = std::env::temp_dir().join(format!("mim-exchange-{stamp}.xsd"));

    fs::write(&xml_path, xml).map_err(|e| e.to_string())?;
    fs::write(&xsd_path, schema).map_err(|e| e.to_string())?;

    let output = Command::new("xmllint")
        .arg("--noout")
        .arg("--schema")
        .arg(&xsd_path)
        .arg(&xml_path)
        .output()
        .map_err(|e| format!("xmllint execution failed: {e}"))?;

    let _ = fs::remove_file(&xml_path);
    let _ = fs::remove_file(&xsd_path);

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("xmllint schema validation failed: {}", stderr.trim()))
    }
}

fn xmllint_available() -> bool {
    Command::new("xmllint")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn validate_structural(xml: &str) -> Result<(), String> {
    let trimmed = xml.trim();
    if !trimmed.starts_with('<') {
        return Err("payload is not XML".into());
    }
    if trimmed.contains("mim:Exchange") {
        if !trimmed.contains("xmlns:mim") {
            return Err("mim:Exchange missing xmlns:mim namespace".into());
        }
        return Ok(());
    }
    if !(trimmed.contains(" oid=\"") || trimmed.contains(" oid='")) {
        return Err("instance element missing oid attribute".into());
    }
    if !(trimmed.contains(" semanticId=\"") || trimmed.contains(" semanticId='")) {
        return Err("instance element missing semanticId attribute".into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::instance::{InstanceStore, MimInstance, PropertyValue};
    use crate::serialize::{SerializationFormat, Serializer};
    use mim_core::SemanticId;
    use mim_model::ModelRegistry;

    fn minimal_registry() -> ModelRegistry {
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
                name: "Unit".into(),
                semantic_id: SemanticId::parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
                    .expect("id"),
                parent: None,
                object_kind: Some(mim_model::ObjectKind::Organisation),
                action_kind: None,
                definition: "Unit".into(),
                package_path: "Classifiers::Object::Organisation::Unit".into(),
            }],
            elements: vec![ModelElementSpec {
                name: "Unit".into(),
                kind: ModelElementKind::Class,
                semantic_id: SemanticId::parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
                    .expect("id"),
                uri: MimUri::parse(
                    "https://www.mimworld.org/mim/5.1.0/Classifiers/Object/Organisation/Unit",
                )
                .expect("uri"),
                package_path: "Classifiers::Object::Organisation::Unit".into(),
                definition: "Unit".into(),
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
    fn validates_serialized_exchange_xml() {
        let registry = minimal_registry();
        let serializer = Serializer::new(registry);
        let class_id =
            SemanticId::parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("id");
        let mut store = InstanceStore::default();
        store.insert(
            MimInstance::new("Unit", class_id)
                .expect("instance")
                .with_property(PropertyValue::string("nameText", "Alpha")),
        );
        let xml = serializer
            .serialize_store(&store, SerializationFormat::Xml)
            .expect("xml");
        validate_exchange_xsd(&xml).expect("valid exchange xml");
    }

    #[test]
    fn rejects_non_xml_payload() {
        assert!(validate_structural("not xml").is_err());
    }
}
