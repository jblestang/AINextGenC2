use std::str::FromStr;

use mim_core::{MimError, MimResult, NilReason, Nillable, SemanticId};
use mim_model::ModelRegistry;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Reader;
use quick_xml::Writer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::instance::{InstanceStore, MimInstance, PropertyValue};

/// JSON-LD `@context` document URL for MIM 5.1 wire profile.
pub const MIM_JSONLD_CONTEXT: &str = "https://www.mimworld.org/mim/5.1.0/context.jsonld";

/// Bundled JSON-LD context document shipped with the runtime (offline validation).
pub const MIM_JSONLD_CONTEXT_DOCUMENT: &str =
    include_str!("../schemas/mim-5.1-context.jsonld");
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerializationFormat {
    Json,
    Xml,
    JsonLd,
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
            SerializationFormat::JsonLd => self.to_jsonld(instance),
            SerializationFormat::Xml => {
                let mut writer = Writer::new(Vec::new());
                self.write_xml_declaration(&mut writer)?;
                self.write_instance_fragment(&mut writer, instance)?;
                bytes_to_string(writer.into_inner())
            }
        }
    }

    pub fn deserialize_instance(
        &self,
        data: &str,
        format: SerializationFormat,
    ) -> MimResult<MimInstance> {
        match format {
            SerializationFormat::Json => serde_json::from_str(data)
                .map_err(|e| MimError::Serialization(e.to_string())),
            SerializationFormat::JsonLd => self.from_jsonld(data),
            SerializationFormat::Xml => self.parse_xml_instances(data)?.into_iter().next().ok_or_else(
                || MimError::Serialization("XML payload contains no MIM instance".into()),
            ),
        }
    }

    pub fn deserialize_store(
        &self,
        data: &str,
        format: SerializationFormat,
    ) -> MimResult<Vec<MimInstance>> {
        match format {
            SerializationFormat::Json => {
                let payload: ExchangePayload = serde_json::from_str(data)
                    .map_err(|e| MimError::Serialization(e.to_string()))?;
                Ok(payload.instances)
            }
            SerializationFormat::JsonLd => {
                let payload: JsonLdExchangePayload = serde_json::from_str(data)
                    .map_err(|e| MimError::Serialization(e.to_string()))?;
                Ok(payload.instances)
            }
            SerializationFormat::Xml => self.parse_xml_instances(data),
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
            SerializationFormat::JsonLd => {
                let payload = JsonLdExchangePayload {
                    context: MIM_JSONLD_CONTEXT.to_owned(),
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

    fn to_jsonld(&self, instance: &MimInstance) -> MimResult<String> {
        let data = serde_json::to_value(instance).map_err(|e| MimError::Serialization(e.to_string()))?;
        let doc = serde_json::json!({
            "@context": MIM_JSONLD_CONTEXT,
            "@type": format!("mim:{}", instance.class_name),
            "@id": instance.oid.as_str(),
            "mim:semanticId": instance.class_semantic_id.to_string(),
            "mim:modelVersion": self.registry.version(),
            "mim:data": data,
        });
        serde_json::to_string_pretty(&doc).map_err(|e| MimError::Serialization(e.to_string()))
    }

    fn from_jsonld(&self, data: &str) -> MimResult<MimInstance> {
        let value: Value = serde_json::from_str(data).map_err(|e| MimError::Serialization(e.to_string()))?;
        if let Some(inner) = value.get("mim:data") {
            return serde_json::from_value(inner.clone()).map_err(|e| MimError::Serialization(e.to_string()));
        }
        serde_json::from_value(value).map_err(|e| MimError::Serialization(e.to_string()))
    }

    fn parse_xml_instances(&self, data: &str) -> MimResult<Vec<MimInstance>> {
        let mut reader = Reader::from_str(data);
        reader.config_mut().trim_text(true);

        let mut instances = Vec::new();
        let mut buf = Vec::new();
        let mut in_exchange = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(start)) => {
                    let name = local_name(start.name().as_ref());
                    if name == "Exchange" {
                        in_exchange = true;
                    } else if in_exchange || !instances.is_empty() || is_instance_start(&start) {
                        let instance = self.parse_instance_element(&mut reader, &start)?;
                        instances.push(instance);
                    }
                }
                Ok(Event::Empty(empty)) if is_instance_start(&empty) => {
                    let instance = self.parse_instance_attributes(&empty)?;
                    instances.push(instance);
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(error) => {
                    return Err(MimError::Serialization(error.to_string()));
                }
            }
            buf.clear();
        }

        if instances.is_empty() {
            return Err(MimError::Serialization(
                "XML payload contains no MIM instance elements".into(),
            ));
        }

        Ok(instances)
    }

    fn parse_instance_element(
        &self,
        reader: &mut Reader<&[u8]>,
        start: &BytesStart<'_>,
    ) -> MimResult<MimInstance> {
        let mut instance = self.parse_instance_attributes(start)?;
        let class_tag = local_name(start.name().as_ref());
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(prop_start)) => {
                    let prop_name = local_name(prop_start.name().as_ref());
                    let property = self.parse_property_element(reader, &prop_start, prop_name)?;
                    instance.properties.push(property);
                }
                Ok(Event::Empty(prop_empty)) => {
                    let prop_name = local_name(prop_empty.name().as_ref());
                    let property = self.parse_property_attributes(&prop_empty, prop_name, None)?;
                    instance.properties.push(property);
                }
                Ok(Event::End(end)) if local_name(end.name().as_ref()) == class_tag => break,
                Ok(Event::Eof) => {
                    return Err(MimError::Serialization(format!(
                        "unexpected end of XML inside <{class_tag}>"
                    )));
                }
                Ok(_) => {}
                Err(error) => return Err(MimError::Serialization(error.to_string())),
            }
            buf.clear();
        }

        Ok(instance)
    }

    fn parse_instance_attributes(&self, start: &BytesStart<'_>) -> MimResult<MimInstance> {
        let class_name = local_name(start.name().as_ref());
        let oid = required_attribute(start, "oid")?;
        let semantic_raw = required_attribute(start, "semanticId")?;
        let semantic_id = SemanticId::parse(&semantic_raw)
            .map_err(|e| MimError::Serialization(e.to_string()))?;

        MimInstance::new(class_name, semantic_id).and_then(|mut instance| {
            instance.oid = crate::oid::ObjectIdentifier::new(oid)?;
            Ok(instance)
        })
    }

    fn parse_property_element(
        &self,
        reader: &mut Reader<&[u8]>,
        start: &BytesStart<'_>,
        prop_name: String,
    ) -> MimResult<PropertyValue> {
        if is_xsi_nil(start) {
            let reason = nil_reason_from_attribute(start);
            return Ok(PropertyValue::nil(prop_name, reason));
        }

        let mut buf = Vec::new();
        let mut text = String::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Text(event)) => text.push_str(event.unescape().unwrap_or_default().as_ref()),
                Ok(Event::CData(event)) => {
                    text.push_str(&String::from_utf8_lossy(event.as_ref()));
                }
                Ok(Event::End(end)) if local_name(end.name().as_ref()) == prop_name => break,
                Ok(Event::Eof) => {
                    return Err(MimError::Serialization(format!(
                        "unexpected end of XML inside <{prop_name}>"
                    )));
                }
                Ok(_) => {}
                Err(error) => return Err(MimError::Serialization(error.to_string())),
            }
            buf.clear();
        }

        self.parse_property_attributes(start, prop_name, Some(text.trim()))
    }

    fn parse_property_attributes(
        &self,
        start: &BytesStart<'_>,
        prop_name: String,
        text: Option<&str>,
    ) -> MimResult<PropertyValue> {
        if is_xsi_nil(start) {
            return Ok(PropertyValue::nil(prop_name, nil_reason_from_attribute(start)));
        }

        let Some(text) = text.filter(|value| !value.is_empty()) else {
            return Ok(PropertyValue {
                name: prop_name,
                semantic_id: None,
                value: Nillable::Absent,
            });
        };

        let value = serde_json::from_str(text)
            .unwrap_or_else(|_| Value::String(text.to_owned()));
        Ok(PropertyValue::json(prop_name, value))
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExchangePayload {
    model_version: String,
    instances: Vec<MimInstance>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JsonLdExchangePayload {
    #[serde(rename = "@context")]
    context: String,
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

fn local_name(name: &[u8]) -> String {
    let raw = String::from_utf8_lossy(name);
    raw.rsplit(':').next().unwrap_or(&raw).to_owned()
}

fn is_instance_start(start: &BytesStart<'_>) -> bool {
    start.attributes().flatten().any(|attr| {
        local_name(attr.key.as_ref()) == "oid"
    })
}

fn required_attribute(start: &BytesStart<'_>, key: &str) -> MimResult<String> {
    for attr in start.attributes().flatten() {
        if local_name(attr.key.as_ref()) == key {
            let value = attr
                .decode_and_unescape_value(reader_decoder())
                .map_err(|e| MimError::Serialization(e.to_string()))?;
            return Ok(value.into_owned());
        }
    }
    Err(MimError::Serialization(format!(
        "MIM instance missing required attribute '{key}'"
    )))
}

fn reader_decoder() -> quick_xml::encoding::Decoder {
    quick_xml::encoding::Decoder {}
}

fn is_xsi_nil(start: &BytesStart<'_>) -> bool {
    start.attributes().flatten().any(|attr| {
        local_name(attr.key.as_ref()) == "nil"
            && attr
                .decode_and_unescape_value(reader_decoder())
                .map(|value| value == "true")
                .unwrap_or(false)
    })
}

fn nil_reason_from_attribute(start: &BytesStart<'_>) -> NilReason {
    for attr in start.attributes().flatten() {
        if local_name(attr.key.as_ref()) == "nilReason" {
            if let Ok(value) = attr.decode_and_unescape_value(reader_decoder()) {
                if let Ok(reason) = NilReason::from_str(value.as_ref()) {
                    return reason;
                }
            }
        }
    }
    NilReason::Unknown
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

    #[test]
    fn xml_roundtrip_instance_and_store() {
        let registry = ModelRegistry::from_manifest(minimal_manifest()).expect("registry");
        let serializer = Serializer::new(registry);
        let class_id =
            SemanticId::parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("id");
        let instance = MimInstance::new("Unit", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "Bravo"));

        let xml = serializer
            .serialize_instance(&instance, SerializationFormat::Xml)
            .expect("xml");
        let restored = serializer
            .deserialize_instance(&xml, SerializationFormat::Xml)
            .expect("restore");
        assert_eq!(restored.class_name, "Unit");
        assert_eq!(
            restored
                .property("nameText")
                .and_then(|p| p.value.as_option())
                .and_then(|v| v.as_str()),
            Some("Bravo")
        );

        let mut store = InstanceStore::default();
        store.insert(instance);
        let store_xml = serializer
            .serialize_store(&store, SerializationFormat::Xml)
            .expect("store xml");
        let restored_store = serializer
            .deserialize_store(&store_xml, SerializationFormat::Xml)
            .expect("store restore");
        assert_eq!(restored_store.len(), 1);
    }

    #[test]
    fn jsonld_roundtrip_instance_and_store() {
        let registry = ModelRegistry::from_manifest(minimal_manifest()).expect("registry");
        let serializer = Serializer::new(registry);
        let class_id =
            SemanticId::parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("id");
        let instance = MimInstance::new("Unit", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "Bravo"));

        let jsonld = serializer
            .serialize_instance(&instance, SerializationFormat::JsonLd)
            .expect("jsonld");
        assert!(jsonld.contains(MIM_JSONLD_CONTEXT));
        assert!(jsonld.contains("mim:semanticId"));
        let restored = serializer
            .deserialize_instance(&jsonld, SerializationFormat::JsonLd)
            .expect("restore");
        assert_eq!(restored.class_name, "Unit");

        let mut store = InstanceStore::default();
        store.insert(instance);
        let store_jsonld = serializer
            .serialize_store(&store, SerializationFormat::JsonLd)
            .expect("store jsonld");
        assert!(store_jsonld.contains("@context"));
        let restored_store = serializer
            .deserialize_store(&store_jsonld, SerializationFormat::JsonLd)
            .expect("store restore");
        assert_eq!(restored_store.len(), 1);
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
