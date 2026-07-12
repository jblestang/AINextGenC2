//! Live HTTPS end-to-end test against `HttpExchangeServer` (TLS + STANAG 4778 envelope + PEP).

use mim_crypto::conformance_keypair;
use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};
use mim_model::Metadata;
use mim_policy::SubjectAttributes;
use mim_runtime::MimInstance;
use mim_transport::envelope::{wrap_put_object, wrap_put_object_with_format};
use mim_transport::message::PutObjectRequest;
use mim_transport::secured::SecuredExchangeBroker;
use mim_transport::wire::{HEADER_MIM_VERSION, MIM_VERSION, WirePayloadFormat};
use mim_transport::{encode_oid_for_path, ExchangeBroker};
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

fn labeled_target(call_sign: &str) -> MimInstance {
    let class_id =
        mim_core::SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
    let mut metadata = Metadata::default();
    metadata.security.policy = mim_core::Nillable::value("NATO".into());
    metadata.security.classification = mim_core::Nillable::value("SECRET".into());
    metadata.security.releasability = mim_core::Nillable::value("USA".into());
    let mut instance = MimInstance::new("Target", class_id)
        .expect("instance")
        .with_property(mim_runtime::PropertyValue::string("nameText", call_sign));
    instance.metadata = metadata;
    instance.oid = mim_runtime::ObjectIdentifier::new(format!("test-oid-{call_sign}"))
        .expect("oid");
    instance
}

fn secured_broker() -> SecuredExchangeBroker {
    SecuredExchangeBroker::from_preset(
        ExchangeBroker::new(test_registry()),
        SubjectAttributes::new("analyst", ClassificationLevel::Secret),
        "DOMAIN-HIGH",
    )
    .expect("secured broker")
}

#[tokio::test]
async fn https_put_get_delete_lifecycle() {
    let keys = conformance_keypair().expect("keys");
    let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
    let instance = labeled_target("HOSTILE-HTTPS");
    let envelope = wrap_put_object(
        &label,
        &PutObjectRequest { instance },
        keys.signing_key(),
    )
    .expect("wrap");
    let body = serde_json::to_string(&envelope).expect("json");

    let tls = TlsIdentity::from_pem(
        include_bytes!("../fixtures/test-server.crt"),
        include_bytes!("../fixtures/test-server.key"),
    )
    .expect("tls");

    let server = HttpExchangeServer::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        tls,
    )
    .with_config(HttpExchangeConfig::conformance().expect("config"));

    let (addr, server_task) = server
        .serve_ephemeral(secured_broker())
        .await
        .expect("serve");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client");

    let base = format!("https://{addr}");

    let put_response = client
        .put(format!("{base}/mip4-ies/v1/objects"))
        .header("content-type", "application/json")
        .header(
            "X-NATO-Confidentiality-Label",
            &envelope.originator_confidentiality_label,
        )
        .body(body)
        .send()
        .await
        .expect("put");
    assert_eq!(put_response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(
        put_response
            .headers()
            .get(HEADER_MIM_VERSION)
            .and_then(|value| value.to_str().ok()),
        Some(MIM_VERSION)
    );

    let put_json: mim_transport::message::PutObjectResponse =
        put_response.json().await.expect("put json");
    let stored_oid = encode_oid_for_path(put_json.oid.as_str());

    let get_response = client
        .get(format!("{base}/mip4-ies/v1/objects/{stored_oid}"))
        .send()
        .await
        .expect("get");
    assert_eq!(get_response.status(), reqwest::StatusCode::OK);

    let delete_response = client
        .delete(format!("{base}/mip4-ies/v1/objects/{stored_oid}"))
        .send()
        .await
        .expect("delete");
    assert_eq!(delete_response.status(), reqwest::StatusCode::OK);

    let gone_response = client
        .get(format!("{base}/mip4-ies/v1/objects/{stored_oid}"))
        .send()
        .await
        .expect("get gone");
    assert_eq!(gone_response.status(), reqwest::StatusCode::GONE);

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn https_get_returns_jsonld_when_accepted() {
    let keys = conformance_keypair().expect("keys");
    let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
    let instance = labeled_target("HOSTILE-JSONLD-HTTPS");
    let envelope = wrap_put_object(
        &label,
        &PutObjectRequest { instance },
        keys.signing_key(),
    )
    .expect("wrap");
    let body = serde_json::to_string(&envelope).expect("json");

    let tls = TlsIdentity::from_pem(
        include_bytes!("../fixtures/test-server.crt"),
        include_bytes!("../fixtures/test-server.key"),
    )
    .expect("tls");

    let server = HttpExchangeServer::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        tls,
    )
    .with_config(HttpExchangeConfig::conformance().expect("config"));

    let (addr, server_task) = server
        .serve_ephemeral(secured_broker())
        .await
        .expect("serve");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client");

    let base = format!("https://{addr}");
    let put_response = client
        .put(format!("{base}/mip4-ies/v1/objects"))
        .header("content-type", "application/json")
        .header(
            "X-NATO-Confidentiality-Label",
            &envelope.originator_confidentiality_label,
        )
        .body(body)
        .send()
        .await
        .expect("put");
    assert_eq!(put_response.status(), reqwest::StatusCode::CREATED);

    let put_json: mim_transport::message::PutObjectResponse =
        put_response.json().await.expect("put json");
    let stored_oid = encode_oid_for_path(put_json.oid.as_str());

    let get_response = client
        .get(format!("{base}/mip4-ies/v1/objects/{stored_oid}"))
        .header("accept", mim_transport::wire::MEDIA_MIM_JSONLD)
        .send()
        .await
        .expect("get");
    assert_eq!(get_response.status(), reqwest::StatusCode::OK);
    let text = get_response.text().await.expect("body");
    assert!(text.contains("@context"));
    assert!(text.contains("mim:semanticId"));

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn https_put_get_jsonld_lifecycle() {
    let keys = conformance_keypair().expect("keys");
    let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
    let instance = labeled_target("HOSTILE-JSONLD-LIFE");
    let envelope = wrap_put_object_with_format(
        &label,
        &PutObjectRequest { instance },
        keys.signing_key(),
        WirePayloadFormat::JsonLd,
    )
    .expect("wrap");
    assert!(envelope.payload.contains("mim:data"));
    let body = serde_json::to_string(&envelope).expect("json");

    let tls = TlsIdentity::from_pem(
        include_bytes!("../fixtures/test-server.crt"),
        include_bytes!("../fixtures/test-server.key"),
    )
    .expect("tls");

    let server = HttpExchangeServer::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        tls,
    )
    .with_config(HttpExchangeConfig::conformance().expect("config"));

    let (addr, server_task) = server
        .serve_ephemeral(secured_broker())
        .await
        .expect("serve");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client");

    let base = format!("https://{addr}");
    let put_response = client
        .put(format!("{base}/mip4-ies/v1/objects"))
        .header("content-type", "application/json")
        .header(
            "X-NATO-Confidentiality-Label",
            &envelope.originator_confidentiality_label,
        )
        .body(body)
        .send()
        .await
        .expect("put");
    assert_eq!(put_response.status(), reqwest::StatusCode::CREATED);

    let put_json: mim_transport::message::PutObjectResponse =
        put_response.json().await.expect("put json");
    let stored_oid = encode_oid_for_path(put_json.oid.as_str());

    let get_response = client
        .get(format!("{base}/mip4-ies/v1/objects/{stored_oid}"))
        .header("accept", mim_transport::wire::MEDIA_MIM_JSONLD)
        .send()
        .await
        .expect("get");
    assert_eq!(get_response.status(), reqwest::StatusCode::OK);
    let text = get_response.text().await.expect("body");
    assert!(text.contains("@context"));
    assert!(text.contains("mim:semanticId"));
    assert!(text.contains("HOSTILE-JSONLD-LIFE"));

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn lab_config_uses_conformance_trust_store() {
    let config = HttpExchangeConfig::lab().expect("config");
    let keys = conformance_keypair().expect("keys");
    assert_eq!(
        config
            .trust_store
            .primary()
            .expect("primary")
            .key_id,
        keys.verifying_key().key_id
    );
}
