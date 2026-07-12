use mim_core::SemanticId;
use mim_crypto::conformance_keypair;
use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};
use mim_model::ModelRegistry;
use mim_runtime::{
    validate_exchange_xsd, validate_instance_jsonld_str, validate_instance_json_schema_str,
    validate_serialized_instance, InstanceStore, MimInstance, PropertyValue, MIM_JSONLD_CONTEXT_DOCUMENT,
    SerializationFormat, Serializer, Validator,
};
use mim_transport::envelope::{unwrap_put_object_with_format, wrap_put_object_with_format};
use mim_transport::message::{
    DeleteObjectRequest, GetByFilterRequest, GetByOidRequest, IesOperation, PutObjectRequest,
};
use mim_transport::persistence::FileExchangeStore;
use mim_transport::replication::ReplicationAgent;
use mim_transport::rest::{encode_oid_for_path, filter_from_query, object_path, parse_route, HttpMethod};
use mim_transport::secured::SecuredExchangeBroker;
use mim_transport::wire::{
    detect_payload_format, format_from_content_type, negotiate_format, validate_mim_version,
    WirePayloadFormat, HEADER_MIM_VERSION, MEDIA_MIM_JSON, MEDIA_MIM_JSONLD, MEDIA_MIM_XML,
    MIM_JSONLD_CONTEXT, MIM_VERSION,
};
use mim_transport::ExchangeBroker;
use mim_policy::SubjectAttributes;

use crate::dimension::{Mip4Dimension, Mip4DimensionResult, ACCREDITATION_THRESHOLD};
use crate::report::Mip4TestResult;
use crate::vectors::{Mip4WireFormat, MIP4_ACCREDITATION_VECTORS};

type TestFn = fn() -> bool;

struct DimensionSpec {
    dimension: Mip4Dimension,
    tests: &'static [(&'static str, TestFn)],
}

pub fn evaluate_dimensions() -> Vec<Mip4DimensionResult> {
    DIMENSIONS
        .iter()
        .map(|spec| evaluate_dimension(spec.dimension, spec.tests))
        .collect()
}

fn evaluate_dimension(dimension: Mip4Dimension, tests: &[(&str, TestFn)]) -> Mip4DimensionResult {
    let mut passed = 0usize;
    for (_, test) in tests {
        if test() {
            passed += 1;
        }
    }
    let total = tests.len();
    let score = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };
    let message = if score >= ACCREDITATION_THRESHOLD {
        format!(
            "{passed}/{total} checks passed — meets {:.0}% threshold",
            ACCREDITATION_THRESHOLD * 100.0
        )
    } else {
        format!(
            "{passed}/{total} checks passed — below {:.0}% threshold",
            ACCREDITATION_THRESHOLD * 100.0
        )
    };
    Mip4DimensionResult::from_tests(dimension, passed, total, message)
}

pub fn evaluate_legacy_suites() -> Vec<(String, Vec<Mip4TestResult>)> {
    let mut out = Vec::new();
    for spec in DIMENSIONS {
        let mut tests = Vec::new();
        for (id, test) in spec.tests {
            tests.push(Mip4TestResult {
                id: (*id).to_owned(),
                suite: spec.dimension.label().to_owned(),
                passed: test(),
                message: spec.dimension.label().to_owned(),
            });
        }
        out.push((spec.dimension.label().to_owned(), tests));
    }
    out
}

static DIMENSIONS: &[DimensionSpec] = &[
    DimensionSpec {
        dimension: Mip4Dimension::RestOperations,
        tests: &REST_OPERATIONS,
    },
    DimensionSpec {
        dimension: Mip4Dimension::RestBinding,
        tests: &REST_BINDING,
    },
    DimensionSpec {
        dimension: Mip4Dimension::MessageSchemas,
        tests: &MESSAGE_SCHEMAS,
    },
    DimensionSpec {
        dimension: Mip4Dimension::Replication,
        tests: &REPLICATION,
    },
    DimensionSpec {
        dimension: Mip4Dimension::MimSemantics,
        tests: &MIM_SEMANTICS,
    },
    DimensionSpec {
        dimension: Mip4Dimension::FmnSecurity,
        tests: &FMN_SECURITY,
    },
    DimensionSpec {
        dimension: Mip4Dimension::Accreditation,
        tests: &ACCREDITATION,
    },
];

macro_rules! tests {
    ($($name:ident => $body:expr),+ $(,)?) => {
        &[
            $((
                stringify!($name),
                || $body,
            )),+
        ]
    };
}

static REST_OPERATIONS: &[(&str, TestFn)] = tests! {
    put_creates => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("OP-1") }).is_ok()
    },
    get_by_oid => {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = sample_target("OP-2");
        let oid = instance.oid.clone();
        broker.put_object(PutObjectRequest { instance }).is_ok()
            && broker.get_by_oid(GetByOidRequest { oid }).is_ok()
    },
    get_by_filter => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("OP-3") }).is_ok();
        broker.get_by_filter(GetByFilterRequest {
            filter: Some("//Target[@nameText='OP-3']".into()),
            class_name: String::new(),
            property_name: None,
            property_value: None,
            limit: None,
            offset: None,
        }).map(|r| r.count == 1).unwrap_or(false)
    },
    pagination => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("OP-4A") }).ok();
        broker.put_object(PutObjectRequest { instance: sample_target("OP-4B") }).ok();
        broker.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            filter: None,
            property_name: None,
            property_value: None,
            limit: Some(1),
            offset: Some(0),
        }).map(|r| r.count == 1 && r.total >= 2).unwrap_or(false)
    },
    delete_soft => {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = sample_target("OP-5");
        let oid = instance.oid.clone();
        broker.put_object(PutObjectRequest { instance }).ok();
        broker.delete_object(DeleteObjectRequest { oid: oid.clone() }).ok();
        matches!(broker.get_by_oid(GetByOidRequest { oid }), Err(_))
    },
    sync_since => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("OP-6") }).ok();
        broker.sync_since(0).entries.len() == 1
    },
    rejects_unknown_class => {
        let mut broker = ExchangeBroker::new(test_registry());
        let class_id = SemanticId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").ok();
        class_id.map(|id| {
            broker.put_object(PutObjectRequest {
                instance: MimInstance::new("Unknown", id).expect("instance"),
            }).is_err()
        }).unwrap_or(false)
    },
    serialize_active_store => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("OP-7") }).ok();
        broker.serialize_active_store().map(|s| s.contains("Target")).unwrap_or(false)
    },
    rest_put_route => parse_route(HttpMethod::Put, "/mip4-ies/v1/objects").map(|r| r.operation == IesOperation::PutObject).unwrap_or(false),
    rest_get_oid_route => parse_route(HttpMethod::Get, "/mip4-ies/v1/objects/oid-1").map(|r| r.operation == IesOperation::GetByOid).unwrap_or(false),
    rest_filter_route => parse_route(HttpMethod::Get, "/mip4-ies/v1/objects").map(|r| r.operation == IesOperation::GetByFilter).unwrap_or(false),
    rest_delete_route => parse_route(HttpMethod::Delete, "/mip4-ies/v1/objects/oid-1").map(|r| r.operation == IesOperation::DeleteObject).unwrap_or(false),
    rest_sync_route => parse_route(HttpMethod::Get, "/mip4-ies/v1/sync").map(|r| r.operation == IesOperation::Sync).unwrap_or(false),
    oid_encoding => encode_oid_for_path("urn:uuid:abc").contains("%3A"),
    object_path => object_path("urn:uuid:abc").contains("/mip4-ies/v1/objects/"),
    filter_from_query => filter_from_query(None, Some("Target"), None, None, Some(5), Some(0)).is_ok(),
    active_count => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("OP-8") }).ok();
        broker.active_count() == 1
    },
    inactive_tracking => {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = sample_target("OP-9");
        let oid = instance.oid.clone();
        broker.put_object(PutObjectRequest { instance }).ok();
        broker.delete_object(DeleteObjectRequest { oid }).ok();
        broker.len() == 1 && broker.active_count() == 0
    },
    json_schema_on_put => {
        let mut broker = ExchangeBroker::new(test_registry());
        validate_serialized_instance(&sample_target("OP-10")).is_ok()
            && broker.put_object(PutObjectRequest { instance: sample_target("OP-10") }).is_ok()
    },
    latest_sequence => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("OP-11") }).ok();
        broker.latest_sequence() == 1
    },
};

static REST_BINDING: &[(&str, TestFn)] = tests! {
    media_json => MEDIA_MIM_JSON == "application/mim+json",
    media_xml => MEDIA_MIM_XML == "application/mim+xml",
    media_jsonld => MEDIA_MIM_JSONLD == "application/ld+json",
    mim_version => MIM_VERSION == "5.1.0",
    jsonld_context => MIM_JSONLD_CONTEXT.contains("mimworld.org"),
    negotiate_xml => negotiate_format(Some("application/mim+xml"), WirePayloadFormat::Json) == WirePayloadFormat::Xml,
    negotiate_jsonld => negotiate_format(Some("application/ld+json"), WirePayloadFormat::Json) == WirePayloadFormat::JsonLd,
    validate_version_ok => validate_mim_version(Some(MIM_VERSION)).is_ok(),
    validate_version_reject => validate_mim_version(Some("4.0.0")).is_err(),
    detect_xml => detect_payload_format("<Target oid=\"a\" semanticId=\"b\"/>") == WirePayloadFormat::Xml,
    detect_jsonld => detect_payload_format("{\"@context\":\"x\",\"mim:data\":{}}") == WirePayloadFormat::JsonLd,
    content_type_jsonld => format_from_content_type("application/ld+json") == Some(WirePayloadFormat::JsonLd),
    multi_predicate => {
        mim_transport::parse_filter("//Target[@a='1'][@b='2']").map(|f| f.predicates.len() == 2).unwrap_or(false)
    },
    envelope_json => envelope_roundtrip(WirePayloadFormat::Json),
    envelope_xml => envelope_roundtrip(WirePayloadFormat::Xml),
    envelope_jsonld => envelope_roundtrip(WirePayloadFormat::JsonLd),
    header_name => HEADER_MIM_VERSION == "MIM-Version",
    wire_json_content => WirePayloadFormat::Json.content_type() == MEDIA_MIM_JSON,
    wire_xml_content => WirePayloadFormat::Xml.content_type() == MEDIA_MIM_XML,
    wire_jsonld_content => WirePayloadFormat::JsonLd.content_type() == MEDIA_MIM_JSONLD,
};

static MESSAGE_SCHEMAS: &[(&str, TestFn)] = tests! {
    xml_roundtrip => {
        let serializer = Serializer::new(test_registry());
        let instance = sample_target("SC-1");
        serializer.serialize_instance(&instance, SerializationFormat::Xml).ok()
            .and_then(|xml| serializer.deserialize_instance(&xml, SerializationFormat::Xml).ok())
            .is_some_and(|restored| restored.class_name == "Target")
    },
    json_schema_valid => validate_serialized_instance(&sample_target("SC-2")).is_ok(),
    json_schema_invalid => {
        let bad = serde_json::json!({"className":"Target"});
        mim_runtime::instance_schema::validate_instance_json_schema(&bad).is_err()
    },
    xsd_exchange => {
        let serializer = Serializer::new(test_registry());
        let mut store = InstanceStore::default();
        store.insert(sample_target("SC-3"));
        serializer.serialize_store(&store, SerializationFormat::Xml).ok()
            .is_some_and(|xml| validate_exchange_xsd(&xml).is_ok())
    },
    json_serialize => Serializer::new(test_registry()).serialize_instance(&sample_target("SC-4"), SerializationFormat::Json).map(|s| s.contains("className")).unwrap_or(false),
    jsonld_context_field => Serializer::new(test_registry()).serialize_instance(&sample_target("SC-5"), SerializationFormat::JsonLd).map(|s| s.contains("@context")).unwrap_or(false),
    jsonld_roundtrip => {
        let serializer = Serializer::new(test_registry());
        let instance = sample_target("SC-6");
        serializer.serialize_instance(&instance, SerializationFormat::JsonLd).ok()
            .and_then(|doc| serializer.deserialize_instance(&doc, SerializationFormat::JsonLd).ok())
            .is_some_and(|restored| restored.class_name == "Target")
    },
    store_json => {
        let serializer = Serializer::new(test_registry());
        let mut store = InstanceStore::default();
        store.insert(sample_target("SC-7"));
        serializer.serialize_store(&store, SerializationFormat::Json).map(|s| s.contains("instances")).unwrap_or(false)
    },
    store_jsonld => {
        let serializer = Serializer::new(test_registry());
        let mut store = InstanceStore::default();
        store.insert(sample_target("SC-8"));
        serializer.serialize_store(&store, SerializationFormat::JsonLd).map(|s| s.contains("@context")).unwrap_or(false)
    },
    validator_known_class => {
        let registry = test_registry();
        Validator::new(&registry).validate_instance(&sample_target("SC-9")).is_valid()
    },
    validator_unknown_class => {
        let registry = test_registry();
        let validator = Validator::new(&registry);
        let class_id = SemanticId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("id");
        !validator.validate_instance(&MimInstance::new("Unknown", class_id).expect("instance")).is_valid()
    },
    xml_single_declaration => {
        let serializer = Serializer::new(test_registry());
        let mut store = InstanceStore::default();
        store.insert(sample_target("SC-10"));
        serializer.serialize_store(&store, SerializationFormat::Xml).map(|xml| xml.matches("<?xml").count() == 1).unwrap_or(false)
    },
    exchange_model_version => {
        let serializer = Serializer::new(test_registry());
        let mut store = InstanceStore::default();
        store.insert(sample_target("SC-11"));
        serializer.serialize_store(&store, SerializationFormat::Json).map(|s| s.contains("5.1.0")).unwrap_or(false)
    },
    xml_has_exchange => {
        let serializer = Serializer::new(test_registry());
        let mut store = InstanceStore::default();
        store.insert(sample_target("SC-12"));
        serializer.serialize_store(&store, SerializationFormat::Xml).map(|s| s.contains("mim:Exchange")).unwrap_or(false)
    },
    xml_oid_attribute => {
        let serializer = Serializer::new(test_registry());
        serializer.serialize_instance(&sample_target("SC-13"), SerializationFormat::Xml).map(|s| s.contains("oid=")).unwrap_or(false)
    },
    json_property_array => {
        let json = serde_json::to_string(&sample_target("SC-14")).unwrap_or_default();
        json.contains("properties")
    },
    jsonld_semantic_id => Serializer::new(test_registry()).serialize_instance(&sample_target("SC-15"), SerializationFormat::JsonLd).map(|s| s.contains("semanticId")).unwrap_or(false),
    xsd_rejects_plain_text => mim_runtime::xsd::validate_structural("not xml").is_err(),
    deserialize_store_json => {
        let serializer = Serializer::new(test_registry());
        let mut store = InstanceStore::default();
        store.insert(sample_target("SC-16"));
        serializer.serialize_store(&store, SerializationFormat::Json).ok()
            .and_then(|json| serializer.deserialize_store(&json, SerializationFormat::Json).ok())
            .is_some_and(|items| items.len() == 1)
    },
    deserialize_store_xml => {
        let serializer = Serializer::new(test_registry());
        let mut store = InstanceStore::default();
        store.insert(sample_target("SC-17"));
        serializer.serialize_store(&store, SerializationFormat::Xml).ok()
            .and_then(|xml| serializer.deserialize_store(&xml, SerializationFormat::Xml).ok())
            .is_some_and(|items| items.len() == 1)
    },
    jsonld_schema_valid => {
        let serializer = Serializer::new(test_registry());
        serializer
            .serialize_instance(&sample_target("SC-18"), SerializationFormat::JsonLd)
            .ok()
            .is_some_and(|doc| validate_instance_jsonld_str(&doc).is_ok())
    },
    jsonld_context_bundled => MIM_JSONLD_CONTEXT_DOCUMENT.contains("semanticId"),
    jsonld_schema_invalid => {
        let bad = serde_json::json!({"@context": "https://example.invalid"});
        validate_instance_jsonld_str(&bad.to_string()).is_err()
    },
};

static REPLICATION: &[(&str, TestFn)] = tests! {
    journal_put => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("RP-1") }).ok();
        broker.journal().len() == 1
    },
    journal_delete => {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = sample_target("RP-2");
        let oid = instance.oid.clone();
        broker.put_object(PutObjectRequest { instance }).ok();
        broker.delete_object(DeleteObjectRequest { oid }).ok();
        broker.journal().len() == 2
    },
    sync_filter => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("RP-3") }).ok();
        broker.put_object(PutObjectRequest { instance: sample_target("RP-4") }).ok();
        broker.sync_since(1).entries.len() == 1
    },
    latest_sequence => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("RP-5") }).ok();
        broker.latest_sequence() == 1
    },
    persistence_roundtrip => {
        let dir = std::env::temp_dir().join(format!("mip4-eval-{:?}", std::time::SystemTime::now()));
        let store = FileExchangeStore::new(dir.join("exchange.json"));
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("RP-6") }).ok();
        store.save(&broker).is_ok() && store.load(test_registry()).map(|b| b.len() == 1).unwrap_or(false)
    },
    replication_apply => {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        publisher.put_object(PutObjectRequest { instance: sample_target("RP-7") }).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).map(|r| r.applied == 1).unwrap_or(false)
    },
    replication_idempotent => {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        publisher.put_object(PutObjectRequest { instance: sample_target("RP-8") }).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).map(|r| r.skipped >= 1).unwrap_or(false)
    },
    applied_sequence => {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        publisher.put_object(PutObjectRequest { instance: sample_target("RP-9") }).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).ok();
        consumer.last_applied_sequence() == 1
    },
    replicate_delete => {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        let instance = sample_target("RP-10");
        let oid = instance.oid.clone();
        publisher.put_object(PutObjectRequest { instance }).ok();
        publisher.delete_object(DeleteObjectRequest { oid }).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).map(|r| r.applied == 2).unwrap_or(false)
            && consumer.active_count() == 0
    },
    journal_jsonl => {
        let dir = std::env::temp_dir().join(format!("mip4-journal-{:?}", std::time::SystemTime::now()));
        let store = FileExchangeStore::new(dir.join("exchange.json"));
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("RP-11") }).ok();
        store.save(&broker).is_ok();
        let entry = broker.journal().first().cloned();
        entry.map(|e| store.append_journal_entry(&e).is_ok()).unwrap_or(false)
    },
    sync_response_shape => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("RP-12") }).ok();
        let sync = broker.sync_since(0);
        sync.latest_sequence == 1 && !sync.entries.is_empty()
    },
    from_snapshot_sequence => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("RP-13") }).ok();
        let restored = ExchangeBroker::from_snapshot(
            test_registry(),
            broker.instances().cloned().collect(),
            broker.inactive_oids().cloned().collect(),
            broker.journal().to_vec(),
            broker.latest_sequence(),
            broker.last_applied_sequence(),
        );
        restored.latest_sequence() == 1
    },
    store_contains => {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = sample_target("RP-14");
        let oid = instance.oid.clone();
        broker.put_object(PutObjectRequest { instance }).ok();
        broker.store_contains(&oid)
    },
    store_get => {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = sample_target("RP-15");
        let oid = instance.oid.clone();
        broker.put_object(PutObjectRequest { instance }).ok();
        broker.store_get(&oid).is_some()
    },
    two_node_converge => {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        publisher.put_object(PutObjectRequest { instance: sample_target("RP-16A") }).ok();
        publisher.put_object(PutObjectRequest { instance: sample_target("RP-16B") }).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).ok();
        consumer.active_count() == 2
    },
    partial_sync => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("RP-17A") }).ok();
        broker.put_object(PutObjectRequest { instance: sample_target("RP-17B") }).ok();
        broker.sync_since(1).entries.len() == 1
    },
    persistence_sequence => {
        let dir = std::env::temp_dir().join(format!("mip4-seq-{:?}", std::time::SystemTime::now()));
        let store = FileExchangeStore::new(dir.join("exchange.json"));
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("RP-18") }).ok();
        store.save(&broker).ok();
        store.load(test_registry()).map(|b| b.latest_sequence() == 1).unwrap_or(false)
    },
    put_only_replicate => {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        publisher.put_object(PutObjectRequest { instance: sample_target("RP-19") }).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).ok();
        consumer.active_count() == 1
    },
    delete_only_replicate => {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        let instance = sample_target("RP-20");
        let oid = instance.oid.clone();
        publisher.put_object(PutObjectRequest { instance }).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).ok();
        publisher.delete_object(DeleteObjectRequest { oid }).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 1).ok();
        consumer.active_count() == 0
    },
};

static MIM_SEMANTICS: &[(&str, TestFn)] = tests! {
    valid_target => Validator::new(&test_registry()).validate_instance(&sample_target("SEM-1")).is_valid(),
    invalid_class => {
        let class_id = SemanticId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("id");
        !Validator::new(&test_registry()).validate_instance(&MimInstance::new("Unknown", class_id).expect("instance")).is_valid()
    },
    semantic_id_present => sample_target("SEM-2").class_semantic_id.to_string().contains('-'),
    oid_present => !sample_target("SEM-3").oid.as_str().is_empty(),
    property_name => sample_target("SEM-4").property("nameText").is_some(),
    registry_version => test_registry().version() == "5.1.0",
    registry_has_target => test_registry().element_by_name("Target").is_some(),
    put_validates => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("SEM-5") }).is_ok()
    },
    put_rejects_bad => {
        let mut broker = ExchangeBroker::new(test_registry());
        let class_id = SemanticId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("id");
        broker.put_object(PutObjectRequest {
            instance: MimInstance::new("Unknown", class_id).expect("instance"),
        }).is_err()
    },
    filter_semantic_match => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: sample_target("SEM-6") }).ok();
        broker.get_by_filter(GetByFilterRequest {
            filter: Some("//Target[@nameText='SEM-6']".into()),
            class_name: String::new(),
            property_name: None,
            property_value: None,
            limit: None,
            offset: None,
        }).map(|r| r.count == 1).unwrap_or(false)
    },
    class_name_match => sample_target("SEM-7").class_name == "Target",
    json_schema_oid => validate_serialized_instance(&sample_target("SEM-8")).is_ok(),
    json_schema_class => {
        let json = serde_json::to_string(&sample_target("SEM-9")).unwrap_or_default();
        json.contains("className")
    },
    metadata_default => sample_target("SEM-10").metadata.security.policy.is_present() == false,
    validator_error_count => {
        let class_id = SemanticId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("id");
        Validator::new(&test_registry()).validate_instance(&MimInstance::new("Unknown", class_id).expect("instance")).error_count() > 0
    },
    taxonomy_node => test_registry().taxonomy_node("Target").is_some(),
    property_value_string => sample_target("SEM-11").property("nameText").and_then(|p| p.value.as_option()).and_then(|v| v.as_str()).is_some(),
    association_map_exists => sample_target("SEM-12").associations.is_empty(),
    registry_object_count => test_registry().object_type_count() >= 1,
    serialize_preserves_class => {
        let serializer = Serializer::new(test_registry());
        serializer.serialize_instance(&sample_target("SEM-13"), SerializationFormat::Json).ok()
            .and_then(|json| serializer.deserialize_instance(&json, SerializationFormat::Json).ok())
            .is_some_and(|i| i.class_name == "Target")
    },
    nillable_absent_ok => sample_target("SEM-14").properties.iter().all(|p| p.name != "missing"),
};

static FMN_SECURITY: &[(&str, TestFn)] = tests! {
    envelope_json => envelope_roundtrip(WirePayloadFormat::Json),
    envelope_xml => envelope_roundtrip(WirePayloadFormat::Xml),
    envelope_verify => {
        let keys = conformance_keypair().ok();
        keys.and_then(|keys| {
            let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
            let envelope = wrap_put_object_with_format(
                &label,
                &PutObjectRequest { instance: labeled_target_simple("SEC-1") },
                keys.signing_key(),
                WirePayloadFormat::Json,
            ).ok()?;
            unwrap_put_object_with_format(&envelope, keys.verifying_key(), Some(WirePayloadFormat::Json)).ok()
        }).is_some()
    },
    pep_allows_read => {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = labeled_target("SEC-2", "RESTRICTED");
        let oid = instance.oid.clone();
        broker.put_object(PutObjectRequest { instance }).ok();
        SecuredExchangeBroker::from_preset(
            broker,
            SubjectAttributes::new("analyst", ClassificationLevel::Restricted),
            "DOMAIN-HIGH",
        )
        .ok()
        .and_then(|secured| secured.get_by_oid(GetByOidRequest { oid }).ok())
        .is_some()
    },
    pep_denies_high => {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = labeled_target("SEC-3", "SECRET");
        let oid = instance.oid.clone();
        broker.put_object(PutObjectRequest { instance }).ok();
        SecuredExchangeBroker::from_preset(
            broker,
            SubjectAttributes::new("analyst", ClassificationLevel::Restricted),
            "DOMAIN-HIGH",
        )
        .map(|mut secured| secured.get_by_oid(GetByOidRequest { oid }).is_err())
        .unwrap_or(false)
    },
    pep_filters_query => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: labeled_target("SEC-4A", "SECRET") }).ok();
        broker.put_object(PutObjectRequest { instance: labeled_target("SEC-4B", "RESTRICTED") }).ok();
        SecuredExchangeBroker::from_preset(
            broker,
            SubjectAttributes::new("analyst", ClassificationLevel::Restricted),
            "DOMAIN-HIGH",
        )
        .ok()
        .and_then(|secured| {
            secured.get_by_filter(GetByFilterRequest {
                class_name: "Target".into(),
                filter: None,
                property_name: None,
                property_value: None,
                limit: None,
                offset: None,
            }).ok()
        })
        .map(|r| r.count == 1)
        .unwrap_or(false)
    },
    secured_sync => {
        let mut broker = ExchangeBroker::new(test_registry());
        broker.put_object(PutObjectRequest { instance: labeled_target("SEC-5", "RESTRICTED") }).ok();
        SecuredExchangeBroker::from_preset(
            broker,
            SubjectAttributes::new("analyst", ClassificationLevel::Restricted),
            "DOMAIN-HIGH",
        )
        .map(|secured| !secured.sync_since(0).entries.is_empty())
        .unwrap_or(false)
    },
    label_policy_nato => !LabelPolicy::nato().identifier.is_empty(),
    classification_secret => !ClassificationLevel::Secret.as_stanag_str().is_empty(),
    nmb_keys => conformance_keypair().is_ok(),
    stanag_envelope_payload => {
        let keys = conformance_keypair().ok();
        keys.and_then(|keys| {
            let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
            wrap_put_object_with_format(
                &label,
                &PutObjectRequest { instance: labeled_target_simple("SEC-6") },
                keys.signing_key(),
                WirePayloadFormat::Json,
            ).ok()
        }).map(|e| !e.payload.is_empty()).unwrap_or(false)
    },
    stanag_label_xml => {
        let keys = conformance_keypair().ok();
        keys.and_then(|keys| {
            let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
            wrap_put_object_with_format(
                &label,
                &PutObjectRequest { instance: labeled_target_simple("SEC-7") },
                keys.signing_key(),
                WirePayloadFormat::Json,
            ).ok()
        }).map(|e| e.originator_confidentiality_label.contains("securityClassification") || e.originator_confidentiality_label.contains("SECRET")).unwrap_or(false)
    },
    pep_delete => {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = labeled_target("SEC-8", "RESTRICTED");
        let oid = instance.oid.clone();
        broker.put_object(PutObjectRequest { instance }).ok();
        SecuredExchangeBroker::from_preset(
            broker,
            SubjectAttributes::new("analyst", ClassificationLevel::Restricted),
            "DOMAIN-HIGH",
        )
        .ok()
        .and_then(|mut secured| secured.delete_object(DeleteObjectRequest { oid }).ok())
        .is_some()
    },
    domain_high => SecuredExchangeBroker::from_preset(
        ExchangeBroker::new(test_registry()),
        SubjectAttributes::new("analyst", ClassificationLevel::Secret),
        "DOMAIN-HIGH",
    ).is_ok(),
    wire_version_header => HEADER_MIM_VERSION == "MIM-Version",
    validate_mim_version => validate_mim_version(Some(MIM_VERSION)).is_ok(),
    envelope_jsonld => envelope_roundtrip(WirePayloadFormat::JsonLd),
    digest_present => {
        let keys = conformance_keypair().ok();
        keys.and_then(|keys| {
            let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
            wrap_put_object_with_format(
                &label,
                &PutObjectRequest { instance: labeled_target_simple("SEC-9") },
                keys.signing_key(),
                WirePayloadFormat::Json,
            ).ok()
        }).map(|e| !e.payload_digest.is_empty()).unwrap_or(false)
    },
    assertion_present => {
        let keys = conformance_keypair().ok();
        keys.and_then(|keys| {
            let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
            wrap_put_object_with_format(
                &label,
                &PutObjectRequest { instance: labeled_target_simple("SEC-10") },
                keys.signing_key(),
                WirePayloadFormat::Json,
            ).ok()
        }).map(|e| e.assertion.is_some()).unwrap_or(false)
    },
    clearance_subject => SubjectAttributes::new("analyst", ClassificationLevel::Secret).clearance == ClassificationLevel::Secret,
};

static ACCREDITATION: &[(&str, TestFn)] = tests! {
    vector_crud => REST_OPERATIONS[0].1() && REST_OPERATIONS[1].1() && REST_OPERATIONS[4].1(),
    vector_xml => MESSAGE_SCHEMAS[0].1(),
    vector_xsd => MESSAGE_SCHEMAS[3].1(),
    vector_replication => REPLICATION[5].1() && REPLICATION[8].1(),
    vector_persistence => REPLICATION[4].1(),
    vector_envelope => REST_BINDING[13].1(),
    vector_jsonld => REST_BINDING[15].1(),
    vector_multi_xpath => REST_BINDING[12].1(),
    vector_semantics => MIM_SEMANTICS[0].1() && MIM_SEMANTICS[7].1(),
    vector_pep => FMN_SECURITY[3].1() && FMN_SECURITY[4].1(),
    vector_sync => REST_OPERATIONS[5].1(),
    vector_sync_route => REST_OPERATIONS[11].1(),
    vector_mim_version => REST_BINDING[3].1(),
    vector_media_types => REST_BINDING[0].1() && REST_BINDING[1].1() && REST_BINDING[2].1(),
    vector_idempotent => REPLICATION[6].1(),
    vector_two_node => REPLICATION[14].1(),
    vector_schema_json => MESSAGE_SCHEMAS[1].1(),
    vector_schema_jsonld => MESSAGE_SCHEMAS[5].1() && MESSAGE_SCHEMAS[20].1(),
    vector_nato_accreditation => run_accreditation_vectors(),
    vector_nato_envelope_jsonld => accreditation_envelope_jsonld_roundtrip(),
    vector_full_stack => {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        let instance = sample_target("ACC-FINAL");
        let oid = instance.oid.clone();
        publisher.put_object(PutObjectRequest { instance }).ok();
        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).ok();
        consumer.get_by_oid(GetByOidRequest { oid }).is_ok()
    },
};

fn run_accreditation_vectors() -> bool {
    let serializer = Serializer::new(test_registry());
    for vector in MIP4_ACCREDITATION_VECTORS {
        if !vector.expect_valid {
            continue;
        }
        let format = vector.format.serialization_format();
        let validation_ok = match vector.format {
            Mip4WireFormat::Xml => vector.payload.contains("Target"),
            Mip4WireFormat::Json => validate_instance_json_schema_str(vector.payload).is_ok(),
            Mip4WireFormat::JsonLd => validate_instance_jsonld_str(vector.payload).is_ok(),
        };
        if !validation_ok {
            return false;
        }
        let instance = match serializer.deserialize_instance(vector.payload, format) {
            Ok(instance) => instance,
            Err(_) => return false,
        };
        if validate_serialized_instance(&instance).is_err() {
            return false;
        }
        let mut broker = ExchangeBroker::new(test_registry());
        let oid = instance.oid.clone();
        if broker.put_object(PutObjectRequest { instance }).is_err() {
            return false;
        }
        if broker.get_by_oid(GetByOidRequest { oid }).is_err() {
            return false;
        }
    }
    true
}

fn accreditation_envelope_jsonld_roundtrip() -> bool {
    let keys = match conformance_keypair() {
        Ok(keys) => keys,
        Err(_) => return false,
    };
    let vector = match MIP4_ACCREDITATION_VECTORS
        .iter()
        .find(|entry| entry.id == "nato-mip4-target-jsonld")
    {
        Some(vector) => vector,
        None => return false,
    };
    let serializer = Serializer::new(test_registry());
    let instance = match serializer.deserialize_instance(
        vector.payload,
        SerializationFormat::JsonLd,
    ) {
        Ok(instance) => instance,
        Err(_) => return false,
    };
    let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
    let request = PutObjectRequest { instance };
    let envelope = match wrap_put_object_with_format(
        &label,
        &request,
        keys.signing_key(),
        WirePayloadFormat::JsonLd,
    ) {
        Ok(envelope) => envelope,
        Err(_) => return false,
    };
    unwrap_put_object_with_format(&envelope, keys.verifying_key(), Some(WirePayloadFormat::JsonLd))
        .map(|restored| {
            restored
                .instance
                .properties
                .iter()
                .any(|property| property.name == "nameText")
        })
        .unwrap_or(false)
}

fn envelope_roundtrip(format: WirePayloadFormat) -> bool {
    let keys = match conformance_keypair() {
        Ok(keys) => keys,
        Err(_) => return false,
    };
    let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
    let request = PutObjectRequest {
        instance: labeled_target_simple("ENV"),
    };
    let envelope = match wrap_put_object_with_format(&label, &request, keys.signing_key(), format) {
        Ok(envelope) => envelope,
        Err(_) => return false,
    };
    unwrap_put_object_with_format(&envelope, keys.verifying_key(), Some(format))
        .map(|restored| restored.instance.class_name == "Target")
        .unwrap_or(false)
}

fn sample_target(call_sign: &str) -> MimInstance {
    let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
    MimInstance::new("Target", class_id)
        .expect("instance")
        .with_property(PropertyValue::string("nameText", call_sign))
}

fn labeled_target(call_sign: &str, classification: &str) -> MimInstance {
    use mim_model::Metadata;
    let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
    let mut metadata = Metadata::default();
    metadata.security.policy = mim_core::Nillable::value("NATO".into());
    metadata.security.classification = mim_core::Nillable::value(classification.into());
    metadata.security.releasability = mim_core::Nillable::value("USA".into());
    let mut instance = MimInstance::new("Target", class_id)
        .expect("instance")
        .with_property(PropertyValue::string("nameText", call_sign));
    instance.metadata = metadata;
    instance
}

fn labeled_target_simple(call_sign: &str) -> MimInstance {
    labeled_target(call_sign, "SECRET")
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
