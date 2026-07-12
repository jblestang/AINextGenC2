//! HTTPS federation sync with live FMN OpenLDAP PIP (CI OpenLDAP service).

use mim_labeling::ClassificationLevel;
use mim_model::Metadata;
use mim_policy::SubjectResolver;
use mim_runtime::{MimInstance, PropertyValue};
use mim_transport::{ExchangeBroker, SecuredExchangeBroker};
use mim_transport_http::{HttpExchangeConfig, HttpExchangeServer, HttpFederationClient, TlsIdentity};

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
    let usa_subject = mim_policy::SubjectAttributes::new(
        "usa-sensor-operator",
        ClassificationLevel::Secret,
    )
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

fn live_ldap_exchange_config() -> HttpExchangeConfig {
    let config_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/fmn-ldap-pip-ci.toml");
    std::env::set_var("MIM_LDAP_PIP_CONFIG", config_path);
    std::env::set_var("MIM_LDAP_BIND_PASSWORD", "ci-ldap-admin");

    let kp = mim_crypto::conformance_keypair().expect("keys");
    HttpExchangeConfig {
        trust_store: mim_crypto::NmbTrustStore::from_verifying_keys([kp.verifying_key().clone()]),
        subject_resolver: SubjectResolver::from_env().expect("live LDAP resolver"),
        require_client_identity: true,
        fallback_subject: None,
    }
}

#[tokio::test]
#[ignore = "requires FMN OpenLDAP (CI: docker-compose.ldap-ci.yml; local: scripts/ci/ldap-e2e.sh)"]
async fn live_ldap_identity_pep_filtered_sync() {
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
    .with_config(live_ldap_exchange_config());

    let (addr, server_task) = server
        .serve_ephemeral(publisher)
        .await
        .expect("serve");

    let sync_url = format!("https://{addr}/mip4-ies/v1/sync");
    let client = HttpFederationClient::new_lab(&sync_url)
        .expect("client")
        .with_client_cn("gbr-analyst.nato.mil")
        .expect("cn");

    let mut consumer = ExchangeBroker::new(registry);
    let report = client
        .replicate_into(&mut consumer, 0)
        .await
        .expect("replicate");

    assert_eq!(
        report.applied, 2,
        "live LDAP GBR analyst receives coalition-releasable objects only"
    );

    server_task.abort();
    let _ = server_task.await;
}
