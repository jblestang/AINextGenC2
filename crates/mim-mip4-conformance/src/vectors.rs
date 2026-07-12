//! NATO-style MIP4-IES accreditation test vectors (FMN interop baseline).

use mim_runtime::SerializationFormat;

/// Wire format for an accreditation vector payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mip4WireFormat {
    Xml,
    Json,
    JsonLd,
}

impl Mip4WireFormat {
    pub fn serialization_format(self) -> SerializationFormat {
        match self {
            Self::Xml => SerializationFormat::Xml,
            Self::Json => SerializationFormat::Json,
            Self::JsonLd => SerializationFormat::JsonLd,
        }
    }
}

/// Single accreditation vector: deserialize, validate, and broker CRUD.
pub struct Mip4AccreditationVector {
    pub id: &'static str,
    pub description: &'static str,
    pub format: Mip4WireFormat,
    pub payload: &'static str,
    pub expect_valid: bool,
}

/// FMN-aligned accreditation vectors (internal baseline until NATO ships official suite).
pub const MIP4_ACCREDITATION_VECTORS: &[Mip4AccreditationVector] = &[
    Mip4AccreditationVector {
        id: "nato-mip4-target-xml",
        description: "NATO-style Target instance (MIM XML)",
        format: Mip4WireFormat::Xml,
        payload: include_str!("../fixtures/nato-mip4-target.xml"),
        expect_valid: true,
    },
    Mip4AccreditationVector {
        id: "nato-mip4-target-json",
        description: "NATO-style Target instance (MIM JSON)",
        format: Mip4WireFormat::Json,
        payload: include_str!("../fixtures/nato-mip4-target.json"),
        expect_valid: true,
    },
    Mip4AccreditationVector {
        id: "nato-mip4-target-jsonld",
        description: "NATO-style Target instance (JSON-LD wire profile)",
        format: Mip4WireFormat::JsonLd,
        payload: include_str!("../fixtures/nato-mip4-target.jsonld"),
        expect_valid: true,
    },
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::SemanticId;
    use mim_model::ModelRegistry;
    use mim_runtime::{
        validate_instance_jsonld_str, validate_instance_json_schema_str, validate_serialized_instance,
        MimInstance, PropertyValue, SerializationFormat, Serializer,
    };
    use mim_transport::message::{GetByOidRequest, PutObjectRequest};
    use mim_transport::ExchangeBroker;

    use super::*;

    fn test_registry() -> ModelRegistry {
        use mim_core::MimUri;
        use mim_model::manifest::{ModelElementKind, ModelElementSpec};
        use mim_model::TaxonomyNode;

        ModelRegistry::from_manifest(mim_model::MimManifest {
            version: "5.1.0".into(),
            release_date: "2020-09-28".into(),
            description: "conformance".into(),
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
    fn accreditation_vectors_deserialize_and_crud() {
        let serializer = Serializer::new(test_registry());
        for vector in MIP4_ACCREDITATION_VECTORS {
            let format = vector.format.serialization_format();
            if vector.format == Mip4WireFormat::Json {
                validate_instance_json_schema_str(vector.payload).expect("json schema");
            }
            if vector.format == Mip4WireFormat::JsonLd {
                validate_instance_jsonld_str(vector.payload).expect("jsonld schema");
            }
            let instance = serializer
                .deserialize_instance(vector.payload, format)
                .expect(vector.id);
            validate_serialized_instance(&instance).expect("instance schema");
            let mut broker = ExchangeBroker::new(test_registry());
            let oid = instance.oid.clone();
            broker
                .put_object(PutObjectRequest { instance })
                .expect("put");
            broker.get_by_oid(GetByOidRequest { oid }).expect("get");
        }
    }

    #[test]
    #[ignore = "helper to regenerate fixtures"]
    fn dump_canonical_vector_fixtures() {
        use mim_runtime::{MimInstance, ObjectIdentifier, PropertyValue};

        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        let mut instance = MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "HOSTILE-NATO-1"));
        instance.oid = ObjectIdentifier::new("urn:uuid:nato-fixture-target-001").expect("oid");
        let serializer = Serializer::new(test_registry());
        let json = serializer
            .serialize_instance(&instance, SerializationFormat::Json)
            .expect("json");
        let jsonld = serializer
            .serialize_instance(&instance, SerializationFormat::JsonLd)
            .expect("jsonld");
        println!("JSON:\n{json}");
        println!("JSONLD:\n{jsonld}");
    }
}
