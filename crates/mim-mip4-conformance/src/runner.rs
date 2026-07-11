use mim_core::SemanticId;
use mim_crypto::conformance_keypair;
use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};
use mim_model::ModelRegistry;
use mim_runtime::{MimInstance, PropertyValue, SerializationFormat, Serializer};
use mim_runtime::{validate_exchange_xsd, InstanceStore};
use mim_transport::envelope::{unwrap_put_object_with_format, wrap_put_object_with_format};
use mim_transport::message::{
    DeleteObjectRequest, GetByFilterRequest, GetByOidRequest, PutObjectRequest,
};
use mim_transport::persistence::FileExchangeStore;
use mim_transport::wire::{WirePayloadFormat, MEDIA_MIM_JSON, MEDIA_MIM_XML, MIM_VERSION};
use mim_transport::ExchangeBroker;

use crate::report::{Mip4ConformanceReport, Mip4SuiteResult, Mip4TestResult};

/// Runs the MIP4-IES conformance test suite.
#[derive(Clone, Debug, Default)]
pub struct Mip4ConformanceRunner;

impl Mip4ConformanceRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self) -> Mip4ConformanceReport {
        let suites = vec![
            self.suite_wire_media_types(),
            self.suite_xml_roundtrip(),
            self.suite_xsd_validation(),
            self.suite_broker_crud(),
            self.suite_replication_journal(),
            self.suite_persistence(),
            self.suite_rest_envelope_payloads(),
        ];

        let total = suites.iter().map(|s| s.total).sum::<usize>();
        let passed = suites.iter().map(|s| s.passed).sum::<usize>();
        let overall_score = if total == 0 {
            0.0
        } else {
            passed as f64 / total as f64
        };
        let is_fully_compliant = passed == total && total > 0;

        let mut recommendations = Vec::new();
        for suite in &suites {
            for test in &suite.tests {
                if !test.passed {
                    recommendations.push(format!(
                        "[{}] {}: {}",
                        suite.name, test.id, test.message
                    ));
                }
            }
        }
        if recommendations.is_empty() {
            recommendations.push("All MIP4-IES conformance vectors passed.".into());
        }

        Mip4ConformanceReport {
            overall_score,
            is_fully_compliant,
            suites,
            recommendations,
        }
    }

    fn suite_wire_media_types(&self) -> Mip4SuiteResult {
        let mut tests = Vec::new();
        tests.push(test(
            "wire-001",
            "Wire media types",
            MEDIA_MIM_JSON == "application/mim+json" && MEDIA_MIM_XML == "application/mim+xml",
            "official MIM media types registered",
        ));
        tests.push(test(
            "wire-002",
            "Wire media types",
            MIM_VERSION == "5.1.0",
            "MIM-Version header constant",
        ));
        finalize_suite("MIP4-IES wire binding", tests)
    }

    fn suite_xml_roundtrip(&self) -> Mip4SuiteResult {
        let registry = test_registry();
        let serializer = Serializer::new(registry);
        let instance = sample_target("ALPHA-1");
        let mut tests = Vec::new();

        let xml = match serializer.serialize_instance(&instance, SerializationFormat::Xml) {
            Ok(xml) => xml,
            Err(err) => {
                tests.push(test(
                    "xml-001",
                    "XML roundtrip",
                    false,
                    err.to_string(),
                ));
                return finalize_suite("MIM XML serialization", tests);
            }
        };

        let restored = serializer.deserialize_instance(&xml, SerializationFormat::Xml);
        tests.push(match restored {
            Ok(value) => test(
                "xml-001",
                "XML roundtrip",
                value.class_name == "Target",
                "instance XML roundtrip",
            ),
            Err(err) => test("xml-001", "XML roundtrip", false, err.to_string()),
        });

        finalize_suite("MIM XML serialization", tests)
    }

    fn suite_xsd_validation(&self) -> Mip4SuiteResult {
        let registry = test_registry();
        let serializer = Serializer::new(registry);
        let mut store = InstanceStore::default();
        store.insert(sample_target("XSD-1"));

        let mut tests = Vec::new();
        let xml = match serializer.serialize_store(&store, SerializationFormat::Xml) {
            Ok(xml) => xml,
            Err(err) => {
                tests.push(test("xsd-001", "XSD validation", false, err.to_string()));
                return finalize_suite("MIM exchange XSD", tests);
            }
        };

        let validation = validate_exchange_xsd(&xml);
        tests.push(match validation {
            Ok(()) => test("xsd-001", "XSD validation", true, "exchange XML validates"),
            Err(err) => test("xsd-001", "XSD validation", false, err),
        });

        finalize_suite("MIM exchange XSD", tests)
    }

    fn suite_broker_crud(&self) -> Mip4SuiteResult {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = sample_target("CRUD-1");
        let oid = instance.oid.clone();
        let mut tests = Vec::new();

        let put = broker.put_object(PutObjectRequest {
            instance: instance.clone(),
        });
        tests.push(match put {
            Ok(response) => test(
                "crud-001",
                "Broker CRUD",
                response.created,
                "PutObject creates instance",
            ),
            Err(err) => test("crud-001", "Broker CRUD", false, err.to_string()),
        });

        let get = broker.get_by_oid(GetByOidRequest { oid: oid.clone() });
        tests.push(match get {
            Ok(response) => test(
                "crud-002",
                "Broker CRUD",
                response.instance.class_name == "Target",
                "GetByOID retrieves instance",
            ),
            Err(err) => test("crud-002", "Broker CRUD", false, err.to_string()),
        });

        let filter = broker.get_by_filter(GetByFilterRequest {
            filter: Some("//Target[@nameText='CRUD-1']".into()),
            class_name: String::new(),
            property_name: None,
            property_value: None,
            limit: Some(1),
            offset: None,
        });
        tests.push(match filter {
            Ok(response) => test(
                "crud-003",
                "Broker CRUD",
                response.count == 1 && response.total == 1,
                "GetByFilter with pagination",
            ),
            Err(err) => test("crud-003", "Broker CRUD", false, err.to_string()),
        });

        let delete = broker.delete_object(DeleteObjectRequest { oid });
        tests.push(match delete {
            Ok(response) => test(
                "crud-004",
                "Broker CRUD",
                response.deleted,
                "DeleteObject soft-deletes instance",
            ),
            Err(err) => test("crud-004", "Broker CRUD", false, err.to_string()),
        });

        finalize_suite("MIP4-IES broker operations", tests)
    }

    fn suite_replication_journal(&self) -> Mip4SuiteResult {
        let mut broker = ExchangeBroker::new(test_registry());
        let mut tests = Vec::new();
        let instance = sample_target("SYNC-1");
        let oid = instance.oid.clone();

        let put_ok = broker
            .put_object(PutObjectRequest { instance })
            .is_ok();
        tests.push(test(
            "sync-000",
            "Replication journal",
            put_ok,
            "PutObject recorded",
        ));

        let delete_ok = broker
            .delete_object(DeleteObjectRequest { oid })
            .is_ok();
        tests.push(test(
            "sync-000b",
            "Replication journal",
            delete_ok,
            "DeleteObject recorded",
        ));

        let sync = broker.sync_since(0);
        tests.push(test(
            "sync-001",
            "Replication journal",
            sync.entries.len() == 2 && sync.latest_sequence == 2,
            "journal records PutObject and DeleteObject",
        ));
        tests.push(test(
            "sync-002",
            "Replication journal",
            broker.sync_since(1).entries.len() == 1,
            "sync since sequence filters entries",
        ));

        finalize_suite("MIP4-IES replication journal", tests)
    }

    fn suite_persistence(&self) -> Mip4SuiteResult {
        let mut tests = Vec::new();
        let dir = std::env::temp_dir().join(format!("mim4-conf-{:?}", std::time::SystemTime::now()));
        let store_path = dir.join("exchange.json");
        let file_store = FileExchangeStore::new(store_path);

        let mut broker = ExchangeBroker::new(test_registry());
        broker
            .put_object(PutObjectRequest {
                instance: sample_target("PERSIST-1"),
            })
            .ok();

        let save = file_store.save(&broker);
        tests.push(match save {
            Ok(()) => test("persist-001", "Persistence", true, "snapshot saved"),
            Err(err) => test("persist-001", "Persistence", false, err.to_string()),
        });

        let load = file_store.load(test_registry());
        tests.push(match load {
            Ok(restored) => test(
                "persist-002",
                "Persistence",
                restored.len() == 1 && restored.latest_sequence() == 1,
                "snapshot restored",
            ),
            Err(err) => test("persist-002", "Persistence", false, err.to_string()),
        });

        finalize_suite("MIP4-IES persistence", tests)
    }

    fn suite_rest_envelope_payloads(&self) -> Mip4SuiteResult {
        let keys = match conformance_keypair() {
            Ok(keys) => keys,
            Err(err) => {
                return finalize_suite(
                    "STANAG 4778 REST envelope payloads",
                    vec![test(
                        "env-000",
                        "REST envelope payloads",
                        false,
                        err.to_string(),
                    )],
                );
            }
        };
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let request = PutObjectRequest {
            instance: sample_target("ENV-1"),
        };
        let mut tests = Vec::new();

        for (id, format) in [("env-001", WirePayloadFormat::Json), ("env-002", WirePayloadFormat::Xml)]
        {
            let restored = match wrap_put_object_with_format(
                &label,
                &request,
                keys.signing_key(),
                format,
            ) {
                Ok(envelope) => unwrap_put_object_with_format(
                    &envelope,
                    keys.verifying_key(),
                    Some(format),
                ),
                Err(err) => Err(mim_transport::TransportError::Serialization(err.to_string())),
            };
            tests.push(match restored {
                Ok(value) => test(
                    id,
                    "REST envelope payloads",
                    value.instance.class_name == "Target",
                    format!("{format:?} payload roundtrip"),
                ),
                Err(err) => test(id, "REST envelope payloads", false, err.to_string()),
            });
        }

        finalize_suite("STANAG 4778 REST envelope payloads", tests)
    }
}

fn test(id: &str, suite: &str, passed: bool, message: impl Into<String>) -> Mip4TestResult {
    Mip4TestResult {
        id: id.to_owned(),
        suite: suite.to_owned(),
        passed,
        message: message.into(),
    }
}

fn finalize_suite(name: &str, tests: Vec<Mip4TestResult>) -> Mip4SuiteResult {
    let passed = tests.iter().filter(|test| test.passed).count();
    let total = tests.len();
    Mip4SuiteResult {
        name: name.to_owned(),
        passed,
        failed: total.saturating_sub(passed),
        total,
        tests,
    }
}

fn sample_target(call_sign: &str) -> MimInstance {
    let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
    MimInstance::new("Target", class_id)
        .expect("instance")
        .with_property(PropertyValue::string("nameText", call_sign))
}

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
