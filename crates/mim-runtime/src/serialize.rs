use mim_core::{MimError, MimResult};
use mim_model::ModelRegistry;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Serialize;

use crate::instance::{InstanceStore, MimInstance};

/// Supported MIM serialization formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerializationFormat {
    Json,
    Xml,
}

/// Serializer for MIM instances compatible with MIP4-IES exchange patterns.
#[derive(Clone, Debug)]
pub struct Serializer {
    registry: ModelRegistry,
}

impl Serializer {
    pub fn new(registry: ModelRegistry) -> Self {
        Self { registry }
    }

    pub fn registry(&self) -> &ModelRegistry {
        &self.registry
    }

    pub fn serialize_instance(
        &self,
        instance: &MimInstance,
        format: SerializationFormat,
    ) -> MimResult<String> {
        match format {
            SerializationFormat::Json => self.to_json(instance),
            SerializationFormat::Xml => {
                let mut writer = Writer::new(Vec::new());
                self.write_xml_declaration(&mut writer)?;
                self.write_instance_fragment(&mut writer, instance)?;
                bytes_to_string(writer.into_inner())
            }
        }
    }

    pub fn serialize_store(
        &self,
        store: &InstanceStore,
        format: SerializationFormat,
    ) -> MimResult<String> {
        let instances: Vec<&MimInstance> = store.instances().collect();
        match format {
            SerializationFormat::Json => {
                let payload = ExchangePayload {
                    model_version: self.registry.version().to_owned(),
                    instances: instances.into_iter().cloned().collect(),
                };
                serde_json::to_string_pretty(&payload)
                    .map_err(|e| MimError::Serialization(e.to_string()))
            }
            SerializationFormat::Xml => {
                let mut writer = Writer::new(Vec::new());
                self.write_xml_declaration(&mut writer)?;

                let mut exchange = BytesStart::new("mim:Exchange");
                exchange.push_attribute((
                    "xmlns:mim",
                    "https://www.mimworld.org/mim/exchange",
                ));
                exchange.push_attribute((
                    "xmlns:xsi",
                    "http://www.w3.org/2001/XMLSchema-instance",
                ));
                writer
                    .write_event(Event::Start(exchange))
                    .map_err(|e| MimError::Serialization(e.to_string()))?;

                for instance in instances {
                    self.write_instance_fragment(&mut writer, instance)?;
                }

                writer
                    .write_event(Event::End(BytesEnd::new("mim:Exchange")))
                    .map_err(|e| MimError::Serialization(e.to_string()))?;

                bytes_to_string(writer.into_inner())
            }
        }
    }

    fn to_json(&self, instance: &MimInstance) -> MimResult<String> {
        serde_json::to_string_pretty(instance).map_err(|e| MimError::Serialization(e.to_string()))
    }

    fn write_xml_declaration(&self, writer: &mut Writer<Vec<u8>>) -> MimResult<()> {
        writer
            .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
            .map_err(|e| MimError::Serialization(e.to_string()))
    }

    fn write_instance_fragment(
        &self,
        writer: &mut Writer<Vec<u8>>,
        instance: &MimInstance,
    ) -> MimResult<()> {
        let tag = sanitize_xml_name(&instance.class_name)?;
        let semantic_id = instance.class_semantic_id.to_string();
        let mut start = BytesStart::new(tag.as_str());
        start.push_attribute(("oid", instance.oid.as_str()));
        start.push_attribute(("semanticId", semantic_id.as_str()));
        writer
            .write_event(Event::Start(start))
            .map_err(|e| MimError::Serialization(e.to_string()))?;

        for property in &instance.properties {
            let prop_tag = sanitize_xml_name(&property.name)?;
            let mut prop_start = BytesStart::new(prop_tag.as_str());
            match &property.value {
                mim_core::Nillable::Nil { reason } => {
                    prop_start.push_attribute(("xsi:nil", "true"));
                    prop_start.push_attribute(("nilReason", reason.as_str()));
                    writer
                        .write_event(Event::Empty(prop_start))
                        .map_err(|e| MimError::Serialization(e.to_string()))?;
                }
                mim_core::Nillable::Value { value } => {
                    writer
                        .write_event(Event::Start(prop_start))
                        .map_err(|e| MimError::Serialization(e.to_string()))?;
                    let text = serde_json::to_string(value)
                        .map_err(|e| MimError::Serialization(e.to_string()))?;
                    writer
                        .write_event(Event::Text(quick_xml::events::BytesText::new(&text)))
                        .map_err(|e| MimError::Serialization(e.to_string()))?;
                    writer
                        .write_event(Event::End(BytesEnd::new(prop_tag.as_str())))
                        .map_err(|e| MimError::Serialization(e.to_string()))?;
                }
                mim_core::Nillable::Absent => {}
            }
        }

        writer
            .write_event(Event::End(BytesEnd::new(tag.as_str())))
            .map_err(|e| MimError::Serialization(e.to_string()))?;

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExchangePayload {
    model_version: String,
    instances: Vec<MimInstance>,
}

fn sanitize_xml_name(name: &str) -> MimResult<String> {
    let mut out = String::new();
    for (idx, ch) in name.chars().enumerate() {
        if idx == 0 {
            if ch.is_ascii_alphabetic() || ch == '_' {
                out.push(ch);
            } else if ch.is_ascii_alphanumeric() {
                out.push('_');
                out.push(ch);
            }
        } else if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        return Err(MimError::Serialization(format!(
            "cannot sanitize XML element name from '{name}'"
        )));
    }
    Ok(out)
}

fn bytes_to_string(bytes: Vec<u8>) -> MimResult<String> {
    String::from_utf8(bytes).map_err(|e| MimError::Serialization(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::instance::PropertyValue;
    use mim_core::SemanticId;

    #[test]
    fn serializes_instance_to_json_and_xml() {
        let registry = ModelRegistry::from_manifest(minimal_manifest()).expect("registry");
        let serializer = Serializer::new(registry);
        let class_id =
            SemanticId::parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("id");
        let instance = MimInstance::new("Unit", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "Bravo"));

        let json = serializer
            .serialize_instance(&instance, SerializationFormat::Json)
            .expect("json");
        assert!(json.contains("Bravo"));

        let xml = serializer
            .serialize_instance(&instance, SerializationFormat::Xml)
            .expect("xml");
        assert!(xml.contains("nameText"));
        assert!(xml.contains("Bravo"));
        assert_eq!(xml.matches("<?xml").count(), 1);
    }

    #[test]
    fn store_xml_has_single_declaration() {
        let registry = ModelRegistry::from_manifest(minimal_manifest()).expect("registry");
        let serializer = Serializer::new(registry);
        let class_id =
            SemanticId::parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("id");
        let mut store = InstanceStore::default();
        store.insert(
            MimInstance::new("Unit", class_id)
                .expect("instance")
                .with_property(PropertyValue::string("nameText", "Alpha")),
        );
        store.insert(
            MimInstance::new("Unit", class_id)
                .expect("instance")
                .with_property(PropertyValue::string("nameText", "Bravo")),
        );

        let xml = serializer
            .serialize_store(&store, SerializationFormat::Xml)
            .expect("xml");
        assert_eq!(xml.matches("<?xml").count(), 1);
        assert!(xml.contains("mim:Exchange"));
    }

    fn minimal_manifest() -> mim_model::MimManifest {
        use mim_core::MimUri;
        use mim_model::manifest::{ModelElementKind, ModelElementSpec};
        use mim_model::TaxonomyNode;

        mim_model::MimManifest {
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
        }
    }
}
