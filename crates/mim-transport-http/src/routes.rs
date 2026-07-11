//! MIP4-IES REST route handlers (FMN / MIP4-IES 4.4 binding).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use mim_crypto::NmbTrustStore;
use mim_stanag4778::RestEnvelope;
use mim_transport::envelope::unwrap_put_object;
use mim_transport::message::PutObjectResponse;
use mim_transport::rest::{parse_delete, parse_get_by_oid};
use mim_transport::secured::SecuredExchangeBroker;
use mim_transport::{encode_oid_for_path, filter_from_query, TransportError, TransportResult};
use serde::Deserialize;
use tokio::sync::Mutex;

/// Shared HTTP application state.
#[derive(Clone)]
pub struct AppState {
    pub broker: Arc<Mutex<SecuredExchangeBroker>>,
    pub trust_store: NmbTrustStore,
}

/// Build the MIP4-IES REST router (`/mip4-ies/v1/objects` CRUD).
pub fn exchange_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/mip4-ies/v1/objects/:oid",
            get(get_by_oid).delete(delete_object),
        )
        .route("/mip4-ies/v1/objects", put(put_object).get(get_by_filter))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct FilterQuery {
    filter: Option<String>,
    #[serde(rename = "className")]
    class_name: Option<String>,
    #[serde(rename = "propertyName")]
    property_name: Option<String>,
    #[serde(rename = "propertyValue")]
    property_value: Option<String>,
}

async fn put_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<RestEnvelope>,
) -> Response {
    match handle_put(&state, &headers, envelope).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(err) => map_error(err),
    }
}

async fn get_by_oid(
    State(state): State<AppState>,
    Path(encoded_oid): Path<String>,
) -> Response {
    let oid = percent_decode_path_segment(&encoded_oid);
    let path = format!("/mip4-ies/v1/objects/{oid}");
    match parse_get_by_oid(&path) {
        Ok(request) => {
            let broker = state.broker.lock().await;
            match broker.get_by_oid(request) {
                Ok(response) => (StatusCode::OK, Json(response)).into_response(),
                Err(err) => map_error(err),
            }
        }
        Err(err) => map_error(err),
    }
}

async fn get_by_filter(
    State(state): State<AppState>,
    Query(query): Query<FilterQuery>,
) -> Response {
    let request = match filter_from_query(
        query.filter.as_deref(),
        query.class_name.as_deref(),
        query.property_name.as_deref(),
        query.property_value.as_deref(),
    ) {
        Ok(request) => request,
        Err(err) => return map_error(err),
    };

    let broker = state.broker.lock().await;
    match broker.get_by_filter(request) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => map_error(err),
    }
}

async fn delete_object(
    State(state): State<AppState>,
    Path(encoded_oid): Path<String>,
) -> Response {
    let oid = percent_decode_path_segment(&encoded_oid);
    let path = format!("/mip4-ies/v1/objects/{oid}");
    match parse_delete(&path) {
        Ok(request) => {
            let mut broker = state.broker.lock().await;
            match broker.delete_object(request) {
                Ok(response) => (StatusCode::OK, Json(response)).into_response(),
                Err(err) => map_error(err),
            }
        }
        Err(err) => map_error(err),
    }
}

pub async fn handle_put(
    state: &AppState,
    headers: &HeaderMap,
    envelope: RestEnvelope,
) -> TransportResult<PutObjectResponse> {
    let key_id = envelope
        .assertion
        .as_ref()
        .map(|a| a.signature.key_id.as_str())
        .ok_or_else(|| {
            TransportError::Forbidden("REST envelope missing NMBS assertion".into())
        })?;
    let verifying_key = state
        .trust_store
        .verify_key_for(key_id)
        .map_err(|e| TransportError::Validation(e.to_string()))?
        .clone();
    if headers
        .get("X-NATO-Confidentiality-Label")
        .and_then(|v| v.to_str().ok())
        != Some(envelope.originator_confidentiality_label.as_str())
    {
        return Err(TransportError::Forbidden(
            "REST envelope label header mismatch".into(),
        ));
    }
    let request = unwrap_put_object(&envelope, &verifying_key)?;
    let mut broker = state.broker.lock().await;
    broker.put_object(request)
}

fn percent_decode_path_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hi = hex_nibble(bytes[index + 1]);
            let lo = hex_nibble(bytes[index + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                decoded.push((h << 4) | l);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(decoded).unwrap_or_else(|_| segment.to_owned())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn map_error(error: TransportError) -> Response {
    let status = match &error {
        TransportError::NotFound(_) => StatusCode::NOT_FOUND,
        TransportError::Inactive(_) => StatusCode::GONE,
        TransportError::Forbidden(_) => StatusCode::FORBIDDEN,
        TransportError::InvalidRequest(_) | TransportError::Validation(_) => StatusCode::BAD_REQUEST,
        TransportError::Unsupported(_) => StatusCode::METHOD_NOT_ALLOWED,
        TransportError::Serialization(_) => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (status, error.to_string()).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use mim_core::SemanticId;
    use mim_crypto::{conformance_keypair, NmbTrustStore};
    use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};
    use mim_model::Metadata;
    use mim_policy::SubjectAttributes;
    use mim_runtime::MimInstance;
    use mim_transport::envelope::wrap_put_object;
    use mim_transport::message::PutObjectRequest;
    use mim_transport::ExchangeBroker;
    use tower::ServiceExt;

    use super::*;

    trait WithMetadata {
        fn with_metadata(self, metadata: Metadata) -> Self;
    }

    impl WithMetadata for MimInstance {
        fn with_metadata(mut self, metadata: Metadata) -> Self {
            self.metadata = metadata;
            self
        }
    }

    fn test_registry() -> mim_model::ModelRegistry {
        use mim_core::MimUri;
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
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        let mut metadata = Metadata::default();
        metadata.security.policy = mim_core::Nillable::value("NATO".into());
        metadata.security.classification = mim_core::Nillable::value("SECRET".into());
        metadata.security.releasability = mim_core::Nillable::value("USA".into());
        let mut instance = MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(mim_runtime::PropertyValue::string("nameText", call_sign))
            .with_metadata(metadata);
        instance.oid = mim_runtime::ObjectIdentifier::new(format!("test-oid-{call_sign}"))
            .expect("oid");
        instance
    }

    fn test_app_state() -> AppState {
        let keys = conformance_keypair().expect("keys");
        let secured = SecuredExchangeBroker::from_preset(
            ExchangeBroker::new(test_registry()),
            SubjectAttributes::new("analyst", ClassificationLevel::Secret),
            "DOMAIN-HIGH",
        )
        .expect("secured");
        AppState {
            broker: Arc::new(Mutex::new(secured)),
            trust_store: NmbTrustStore::from_verifying_keys([keys.verifying_key().clone()]),
        }
    }

    fn test_app() -> Router {
        exchange_router(test_app_state())
    }

    #[tokio::test]
    async fn oid_route_matches_single_segment() {
        let app = exchange_router(test_app_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_put_persists_instance_in_broker() {
        let keys = conformance_keypair().expect("keys");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let instance = labeled_target("HOSTILE-1");
        let envelope = wrap_put_object(
            &label,
            &PutObjectRequest { instance },
            keys.signing_key(),
        )
        .expect("wrap");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "X-NATO-Confidentiality-Label",
            envelope
                .originator_confidentiality_label
                .parse()
                .expect("header"),
        );
        let state = test_app_state();
        handle_put(&state, &headers, envelope)
            .await
            .expect("put");
        let broker = state.broker.lock().await;
        assert_eq!(broker.broker().len(), 1);
    }

    #[tokio::test]
    async fn rest_crud_lifecycle_over_http() {
        let keys = conformance_keypair().expect("keys");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let instance = labeled_target("HOSTILE-1");
        let oid = instance.oid.to_string();

        let envelope = wrap_put_object(
            &label,
            &PutObjectRequest { instance },
            keys.signing_key(),
        )
        .expect("wrap");
        let body = serde_json::to_string(&envelope).expect("json");

        let state = test_app_state();
        let app = exchange_router(state.clone());
        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/mip4-ies/v1/objects")
                    .header("content-type", "application/json")
                    .header(
                        "X-NATO-Confidentiality-Label",
                        &envelope.originator_confidentiality_label,
                    )
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(put_response.status(), StatusCode::CREATED);
        let put_bytes = axum::body::to_bytes(put_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let put_json: PutObjectResponse = serde_json::from_slice(&put_bytes).expect("put json");

        {
            let broker = state.broker.lock().await;
            assert_eq!(broker.broker().len(), 1);
            broker
                .get_by_oid(mim_transport::message::GetByOidRequest {
                    oid: put_json.oid.clone(),
                })
                .expect("broker get");
        }

        let stored_oid = encode_oid_for_path(put_json.oid.as_str());

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/mip4-ies/v1/objects/{stored_oid}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(get_response.status(), StatusCode::OK);

        let filter_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mip4-ies/v1/objects?filter=//Target[@nameText='HOSTILE-1']")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(filter_response.status(), StatusCode::OK);

        let delete_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/mip4-ies/v1/objects/{stored_oid}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(delete_response.status(), StatusCode::OK);

        let gone_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/mip4-ies/v1/objects/{stored_oid}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(gone_response.status(), StatusCode::GONE);
    }
}
