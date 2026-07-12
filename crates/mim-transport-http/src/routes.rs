//! MIP4-IES REST route handlers (FMN / MIP4-IES 4.4 binding).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{ACCEPT, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use mim_crypto::NmbTrustStore;
use mim_policy::{SubjectAttributes, SubjectResolver};
use mim_runtime::{SerializationFormat, Serializer};
use mim_stanag4778::RestEnvelope;
use mim_transport::envelope::unwrap_put_object_with_format;
use mim_transport::message::PutObjectResponse;
use mim_transport::rest::{parse_delete, parse_get_by_oid};
use mim_transport::secured::SecuredExchangeBroker;
use mim_transport::wire::{
    format_from_content_type, negotiate_format, validate_mim_version, wire_registry,
    WirePayloadFormat, HEADER_MIM_VERSION, MEDIA_MIM_JSON, MEDIA_MIM_JSONLD, MEDIA_MIM_XML,
    MIM_VERSION,
};
use mim_transport::{
    encode_oid_for_path, filter_from_query, notify_webhooks, ReplicationNotifyPayload,
    TransportError, TransportResult,
};
use mim_crypto::PkiMode;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::federation_client::HttpFederationClient;
use crate::identity::{resolve_request_subject, TlsClientIdentity, HEADER_MIM_CLIENT_CERT_SHA256};

/// Shared HTTP application state.
#[derive(Clone)]
pub struct AppState {
    pub broker: Arc<Mutex<SecuredExchangeBroker>>,
    pub trust_store: NmbTrustStore,
    pub subject_resolver: Arc<SubjectResolver>,
    pub require_client_identity: bool,
    pub fallback_subject: Option<SubjectAttributes>,
    /// Publisher-side webhook targets notified after journal append.
    pub webhook_targets: Arc<Vec<String>>,
    /// Consumer-side publisher sync URL used by the replication notify handler.
    pub federation_pull_url: Option<String>,
    pub federation_client_cn: Option<String>,
    pub federation_pki_mode: PkiMode,
}

/// Build the MIP4-IES REST router (`/mip4-ies/v1/objects` CRUD + replication sync).
pub fn exchange_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/mip4-ies/v1/objects/:oid",
            get(get_by_oid).delete(delete_object),
        )
        .route("/mip4-ies/v1/objects", put(put_object).get(get_by_filter))
        .route("/mip4-ies/v1/sync", get(sync_changes))
        .route("/mip4-ies/v1/replication/notify", post(replication_notify))
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
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SyncQuery {
    since: Option<u64>,
}

async fn put_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let tls_identity = request_tls_identity(&headers);
    if let Err(err) = validate_mim_version(
        headers
            .get(HEADER_MIM_VERSION)
            .and_then(|value| value.to_str().ok()),
    ) {
        return map_error(TransportError::InvalidRequest(err));
    }
    let envelope = match serde_json::from_str::<RestEnvelope>(&body) {
        Ok(envelope) => envelope,
        Err(err) => return map_error(TransportError::Serialization(err.to_string())),
    };
    match handle_put(&state, &headers, tls_identity.as_ref(), envelope).await {
        Ok(response) => {
            let latest = {
                let broker = state.broker.lock().await;
                broker.latest_sequence()
            };
            notify_webhooks(state.webhook_targets.as_ref(), latest);
            negotiated_response(
                &headers,
                WirePayloadFormat::Json,
                StatusCode::CREATED,
                &response,
            )
        }
        Err(err) => map_error(err),
    }
}

async fn get_by_oid(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(encoded_oid): Path<String>,
) -> Response {
    let tls_identity = request_tls_identity(&headers);
    if let Err(err) = validate_mim_version(
        headers
            .get(HEADER_MIM_VERSION)
            .and_then(|value| value.to_str().ok()),
    ) {
        return map_error(TransportError::InvalidRequest(err));
    }
    let format = negotiated_format(&headers);
    let oid = percent_decode_path_segment(&encoded_oid);
    let path = format!("/mip4-ies/v1/objects/{oid}");
    match parse_get_by_oid(&path) {
        Ok(request) => {
            let subject = match resolve_subject_for_request(&state, &headers, tls_identity.as_ref())
            {
                Ok(subject) => subject,
                Err(err) => return map_error(err),
            };
            let broker = state.broker.lock().await;
            match broker.get_by_oid_as(subject, request) {
                Ok(response) => {
                    if format == WirePayloadFormat::Xml || format == WirePayloadFormat::JsonLd {
                        match serialize_instance(&response.instance, format) {
                            Ok(body) => mim_payload_response(format, body),
                            Err(err) => map_error(err),
                        }
                    } else {
                        negotiated_response(&headers, format, StatusCode::OK, &response)
                    }
                }
                Err(err) => map_error(err),
            }
        }
        Err(err) => map_error(err),
    }
}

async fn get_by_filter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<FilterQuery>,
) -> Response {
    let format = negotiated_format(&headers);
    let tls_identity = request_tls_identity(&headers);
    let request = match filter_from_query(
        query.filter.as_deref(),
        query.class_name.as_deref(),
        query.property_name.as_deref(),
        query.property_value.as_deref(),
        query.limit,
        query.offset,
    ) {
        Ok(request) => request,
        Err(err) => return map_error(err),
    };

    let subject = match resolve_subject_for_request(&state, &headers, tls_identity.as_ref()) {
        Ok(subject) => subject,
        Err(err) => return map_error(err),
    };
    let broker = state.broker.lock().await;
    match broker.get_by_filter_as(subject, request) {
        Ok(response) => {
            if format == WirePayloadFormat::Xml || format == WirePayloadFormat::JsonLd {
                match serialize_instances(&response.instances, format) {
                    Ok(body) => mim_payload_response(format, body),
                    Err(err) => map_error(err),
                }
            } else {
                negotiated_response(&headers, format, StatusCode::OK, &response)
            }
        }
        Err(err) => map_error(err),
    }
}

async fn delete_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(encoded_oid): Path<String>,
) -> Response {
    let tls_identity = request_tls_identity(&headers);
    let oid = percent_decode_path_segment(&encoded_oid);
    let path = format!("/mip4-ies/v1/objects/{oid}");
    match parse_delete(&path) {
        Ok(request) => {
            let subject = match resolve_subject_for_request(&state, &headers, tls_identity.as_ref())
            {
                Ok(subject) => subject,
                Err(err) => return map_error(err),
            };
            let mut broker = state.broker.lock().await;
            match broker.delete_object_as(subject, request) {
                Ok(response) => {
                    negotiated_response(&headers, WirePayloadFormat::Json, StatusCode::OK, &response)
                }
                Err(err) => map_error(err),
            }
        }
        Err(err) => map_error(err),
    }
}

async fn sync_changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SyncQuery>,
) -> Response {
    let tls_identity = request_tls_identity(&headers);
    let since = query.since.unwrap_or(0);
    let subject = match resolve_subject_for_request(&state, &headers, tls_identity.as_ref()) {
        Ok(subject) => subject,
        Err(err) => return map_error(err),
    };
    let broker = state.broker.lock().await;
    let response = broker.sync_since_as(subject, since);
    negotiated_response(&headers, WirePayloadFormat::Json, StatusCode::OK, &response)
}

async fn replication_notify(
    State(state): State<AppState>,
    Json(_payload): Json<ReplicationNotifyPayload>,
) -> Response {
    let Some(pull_url) = state.federation_pull_url.clone() else {
        return map_error(TransportError::InvalidRequest(
            "node is not configured as federation consumer (no pull URL)".into(),
        ));
    };
    let client_cn = state
        .federation_client_cn
        .clone()
        .unwrap_or_else(|| "gbr-analyst.nato.mil".into());
    let client = match HttpFederationClient::new_with_mode(&pull_url, state.federation_pki_mode)
        .and_then(|c| c.with_client_cn(client_cn))
    {
        Ok(client) => client,
        Err(err) => return map_error(err),
    };
    let mut broker = state.broker.lock().await;
    let since = broker.broker().last_applied_sequence();
    match client
        .replicate_into(broker.broker_mut(), since)
        .await
    {
        Ok(report) => negotiated_response(
            &HeaderMap::new(),
            WirePayloadFormat::Json,
            StatusCode::OK,
            &report,
        ),
        Err(err) => map_error(err),
    }
}

pub async fn handle_put(
    state: &AppState,
    headers: &HeaderMap,
    tls_identity: Option<&TlsClientIdentity>,
    envelope: RestEnvelope,
) -> TransportResult<PutObjectResponse> {
    let payload_format = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(format_from_content_type)
        .or_else(|| {
            headers
                .get("X-MIM-Payload-Format")
                .and_then(|value| value.to_str().ok())
                .and_then(format_from_content_type)
        })
        .unwrap_or_else(|| mim_transport::detect_payload_format(&envelope.payload));

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
    let request =
        unwrap_put_object_with_format(&envelope, &verifying_key, Some(payload_format))?;
    let subject = resolve_subject_for_request(state, headers, tls_identity)?;
    let mut broker = state.broker.lock().await;
    broker.put_object_as(subject, request)
}

fn policy_error_to_transport(error: mim_policy::PolicyError) -> TransportError {
    match error {
        mim_policy::PolicyError::Denied(msg) => TransportError::Forbidden(msg),
        mim_policy::PolicyError::NotFound(msg) => TransportError::Forbidden(msg),
        mim_policy::PolicyError::Invalid(msg) => TransportError::Validation(msg),
        mim_policy::PolicyError::Validation(msg) => TransportError::Validation(msg),
        mim_policy::PolicyError::Serialization(msg) => TransportError::Serialization(msg),
    }
}

fn resolve_subject_for_request(
    state: &AppState,
    headers: &HeaderMap,
    tls_identity: Option<&TlsClientIdentity>,
) -> TransportResult<SubjectAttributes> {
    resolve_request_subject(
        state.subject_resolver.as_ref(),
        headers,
        tls_identity,
        state.require_client_identity,
    )
    .or_else(|err| {
        if let Some(fallback) = &state.fallback_subject {
            if !state.require_client_identity {
                return Ok(fallback.clone());
            }
        }
        Err(policy_error_to_transport(err))
    })
}

fn request_tls_identity(headers: &HeaderMap) -> Option<TlsClientIdentity> {
    let cn = headers
        .get("X-MIM-Tls-Client-CN")
        .and_then(|value| value.to_str().ok())?
        .to_owned();
    let cert_sha256 = headers
        .get(HEADER_MIM_CLIENT_CERT_SHA256)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    Some(TlsClientIdentity {
        cn,
        cert_sha256,
        subject_dn: headers
            .get("X-MIM-Tls-Client-DN")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    })
}


fn negotiated_format(headers: &HeaderMap) -> WirePayloadFormat {
    negotiate_format(
        headers.get(ACCEPT).and_then(|value| value.to_str().ok()),
        WirePayloadFormat::Json,
    )
}

fn negotiated_response<T: serde::Serialize>(
    _headers: &HeaderMap,
    format: WirePayloadFormat,
    status: StatusCode,
    value: &T,
) -> Response {
    match format {
        WirePayloadFormat::Json | WirePayloadFormat::JsonLd => {
            let mut response = (status, Json(value)).into_response();
            apply_mim_headers(response.headers_mut(), format.content_type());
            response
        }
        WirePayloadFormat::Xml => match serde_json::to_string(value) {
            Ok(json) => {
                let mut response = (status, json).into_response();
                apply_mim_headers(response.headers_mut(), MEDIA_MIM_JSON);
                response
            }
            Err(err) => map_error(TransportError::Serialization(err.to_string())),
        },
    }
}

fn mim_payload_response(format: WirePayloadFormat, body: String) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    apply_mim_headers(response.headers_mut(), format.content_type());
    response
}

fn apply_mim_headers(headers: &mut HeaderMap, content_type: &str) {
    if let Ok(value) = HeaderValue::from_str(MIM_VERSION) {
        headers.insert(HEADER_MIM_VERSION, value);
    }
    if let Ok(value) = HeaderValue::from_str(content_type) {
        headers.insert(CONTENT_TYPE, value);
    }
}

fn serialize_instance(
    instance: &mim_runtime::MimInstance,
    format: WirePayloadFormat,
) -> TransportResult<String> {
    let serializer = Serializer::new(wire_registry().map_err(TransportError::from)?);
    serializer
        .serialize_instance(instance, format.serialization_format())
        .map_err(TransportError::from)
}

fn serialize_instances(
    instances: &[mim_runtime::MimInstance],
    format: WirePayloadFormat,
) -> TransportResult<String> {
    let serializer = Serializer::new(wire_registry().map_err(TransportError::from)?);
    let mut store = mim_runtime::InstanceStore::default();
    for instance in instances {
        store.insert(instance.clone());
    }
    serializer
        .serialize_store(&store, format.serialization_format())
        .map_err(TransportError::from)
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
    use mim_policy::{SubjectAttributes, SubjectResolver};
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
            subject_resolver: Arc::new(SubjectResolver::conformance().expect("resolver")),
            require_client_identity: false,
            fallback_subject: Some(SubjectAttributes::new(
                "analyst",
                ClassificationLevel::Secret,
            )),
            webhook_targets: Arc::new(Vec::new()),
            federation_pull_url: None,
            federation_client_cn: None,
            federation_pki_mode: PkiMode::Lab,
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
        handle_put(&state, &headers, None, envelope)
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
        assert_eq!(
            put_response
                .headers()
                .get(HEADER_MIM_VERSION)
                .and_then(|value| value.to_str().ok()),
            Some(MIM_VERSION)
        );
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

        let sync_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mip4-ies/v1/sync?since=0")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(sync_response.status(), StatusCode::OK);

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

    #[tokio::test]
    async fn get_by_oid_returns_xml_when_accepted() {
        let keys = conformance_keypair().expect("keys");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let instance = labeled_target("HOSTILE-XML");
        let envelope = wrap_put_object(
            &label,
            &PutObjectRequest { instance },
            keys.signing_key(),
        )
        .expect("wrap");
        let body = serde_json::to_string(&envelope).expect("json");

        let state = test_app_state();
        let app = exchange_router(state);
        app.clone()
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

        let stored_oid = encode_oid_for_path("test-oid-HOSTILE-XML");
        let get_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/mip4-ies/v1/objects/{stored_oid}"))
                    .header("accept", MEDIA_MIM_XML)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(get_response.status(), StatusCode::OK);
        assert_eq!(
            get_response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(MEDIA_MIM_XML)
        );
    }

    #[tokio::test]
    async fn get_by_oid_returns_jsonld_when_accepted() {
        let keys = conformance_keypair().expect("keys");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let instance = labeled_target("HOSTILE-JSONLD");
        let envelope = wrap_put_object(
            &label,
            &PutObjectRequest { instance },
            keys.signing_key(),
        )
        .expect("wrap");
        let body = serde_json::to_string(&envelope).expect("json");

        let state = test_app_state();
        let app = exchange_router(state);
        app.clone()
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

        let stored_oid = encode_oid_for_path("test-oid-HOSTILE-JSONLD");
        let get_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/mip4-ies/v1/objects/{stored_oid}"))
                    .header("accept", MEDIA_MIM_JSONLD)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(get_response.status(), StatusCode::OK);
        assert_eq!(
            get_response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(MEDIA_MIM_JSONLD)
        );
        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(text.contains("@context"));
        assert!(text.contains("mim:semanticId"));
    }
}
