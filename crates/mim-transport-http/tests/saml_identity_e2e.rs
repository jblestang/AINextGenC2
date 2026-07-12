//! SAML bearer identity resolves through PEP for HTTPS federation sync.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
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

fn gbr_saml_bearer() -> String {
    let claims = serde_json::json!({
        "subjectId": "gbr-allied-analyst",
        "clearance": "SECRET",
        "nationality": "GBR"
    });
    let token = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("Bearer {token}")
}

#[tokio::test]
async fn saml_bearer_identity_pep_filtered_sync() {
    std::env::set_var("MIM_CONFORMANCE_KEYS", "1");

    let registry = test_registry();
    let publisher = publisher_broker(&registry);

    let tls = TlsIdentity::from_pem(
        include_bytes!("../fixtures/test-server.crt"),
        include_bytes!("../fixtures/test-server.key"),
    )
    .expect("tls");

    let server = HttpExchangeServer::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        tls,
    )
    .with_config(federation_server_config());

    let (addr, server_task) = server
        .serve_ephemeral(publisher)
        .await
        .expect("serve");

    let sync_url = format!("https://{addr}/mip4-ies/v1/sync");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client");

    let response = client
        .get(&sync_url)
        .header("Authorization", gbr_saml_bearer())
        .send()
        .await
        .expect("sync");
    assert!(response.status().is_success(), "sync returned {}", response.status());

    let sync: mim_transport::SyncResponse = response.json().await.expect("sync body");
    assert_eq!(
        sync.entries.len(),
        2,
        "SAML GBR analyst receives coalition-releasable journal entries only"
    );

    server_task.abort();
    let _ = server_task.await;
}
