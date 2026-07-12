//! Coalition replication webhook — notify + pull federation pattern.

use mim_labeling::ClassificationLevel;
use mim_model::Metadata;
use mim_policy::{SubjectAttributes, SubjectResolver};
use mim_runtime::{MimInstance, PropertyValue};
use mim_transport::{ExchangeBroker, SecuredExchangeBroker};
use mim_transport_http::{HttpExchangeConfig, HttpExchangeServer, TlsIdentity};

fn test_registry() -> mim_model::ModelRegistry {
    use mim_core::{MimUri, SemanticId};
    use mim_model::manifest::{ModelElementKind, ModelElementSpec};
    use mim_model::TaxonomyNode;

    mim_model::ModelRegistry::from_manifest(mim_model::MimManifest {
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

fn labeled_target(call_sign: &str, coalition: bool) -> MimInstance {
    let class_id =
        mim_core::SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
    let mut metadata = Metadata::default();
    metadata.security.policy = mim_core::Nillable::value("NATO".into());
    metadata.security.classification = mim_core::Nillable::value("SECRET".into());
    metadata.security.releasability = mim_core::Nillable::value(if coalition {
        "USA,GBR".into()
    } else {
        "USA".into()
    });
    let mut instance = MimInstance::new("Target", class_id)
        .expect("instance")
        .with_property(PropertyValue::string("nameText", call_sign));
    instance.metadata = metadata;
    instance.oid = mim_runtime::ObjectIdentifier::new(format!("fed-oid-{call_sign}"))
        .expect("oid");
    instance
}

fn publisher_broker(registry: &mim_model::ModelRegistry) -> SecuredExchangeBroker {
    let usa_subject = SubjectAttributes::new("usa-sensor-operator", ClassificationLevel::Secret)
        .with_nationality("USA");
    let mut broker = SecuredExchangeBroker::from_preset(
        ExchangeBroker::new(registry.clone()),
        usa_subject,
        "DOMAIN-HIGH",
    )
    .expect("secured");
    broker
        .publish_store(vec![
            labeled_target("COALITION-1", true),
            labeled_target("COALITION-2", true),
            labeled_target("USA-EYES-ONLY", false),
        ])
        .expect("publish");
    broker
}

fn federation_server_config() -> HttpExchangeConfig {
    let kp = mim_crypto::conformance_keypair().expect("keys");
    HttpExchangeConfig {
        trust_store: mim_crypto::NmbTrustStore::from_verifying_keys([kp.verifying_key().clone()]),
        subject_resolver: SubjectResolver::conformance().expect("resolver"),
        require_client_identity: true,
        fallback_subject: None,
    }
}

fn tls_identity() -> TlsIdentity {
    TlsIdentity::from_pem(
        include_bytes!("../fixtures/test-server.crt"),
        include_bytes!("../fixtures/test-server.key"),
    )
    .expect("tls")
}

#[tokio::test]
async fn replication_notify_triggers_pep_filtered_pull() {
    let registry = test_registry();
    let publisher = publisher_broker(&registry);
    let consumer = SecuredExchangeBroker::from_preset(
        ExchangeBroker::new(registry.clone()),
        SubjectAttributes::new("gbr-allied-analyst", ClassificationLevel::Secret)
            .with_nationality("GBR"),
        "DOMAIN-HIGH",
    )
    .expect("consumer");

    let tls = tls_identity();
    let config = federation_server_config();

    let publisher_server = HttpExchangeServer::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        tls.clone(),
    )
    .with_config(config.clone());

    let (publisher_addr, publisher_task) = publisher_server
        .serve_ephemeral(publisher)
        .await
        .expect("publisher");

    let sync_url = format!("https://{publisher_addr}/mip4-ies/v1/sync");

    let consumer_server = HttpExchangeServer::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        tls,
    )
    .with_config(config)
    .with_federation_pull(&sync_url, "gbr-analyst.nato.mil");

    let (consumer_addr, consumer_task) = consumer_server
        .serve_ephemeral(consumer)
        .await
        .expect("consumer");

    let notify_url = format!("https://{consumer_addr}/mip4-ies/v1/replication/notify");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client");

    let response = client
        .post(&notify_url)
        .json(&mim_transport::ReplicationNotifyPayload::new(3))
        .send()
        .await
        .expect("notify");
    assert!(response.status().is_success(), "notify returned {}", response.status());

    let body: mim_transport::ReplicationApplyReport = response.json().await.expect("report");
    assert_eq!(
        body.applied, 2,
        "webhook pull applies coalition-releasable entries only"
    );

    publisher_task.abort();
    consumer_task.abort();
    let _ = publisher_task.await;
    let _ = consumer_task.await;
}
