//! TLS/mTLS MIP4-IES HTTP server with STANAG 4778 REST envelope verification.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use mim_crypto::NmbTrustStore;
use mim_stanag4778::RestEnvelope;
use mim_transport::envelope::unwrap_put_object;
use mim_transport::secured::SecuredExchangeBroker;
use mim_transport::TransportResult;
use rustls::pki_types::CertificateDer;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;

use crate::tls::TlsIdentity;

/// Runtime configuration for HTTPS exchange verification and PKI trust.
#[derive(Clone, Debug)]
pub struct HttpExchangeConfig {
    pub trust_store: NmbTrustStore,
}

impl HttpExchangeConfig {
    pub fn conformance() -> mim_crypto::CryptoResult<Self> {
        let kp = mim_crypto::conformance_keypair()?;
        Ok(Self {
            trust_store: NmbTrustStore::from_verifying_keys([kp.verifying_key().clone()]),
        })
    }
}

impl Default for HttpExchangeConfig {
    fn default() -> Self {
        Self::conformance().expect("conformance trust store")
    }
}

/// MIP4-IES exchange server over HTTPS with STANAG 4778 REST envelopes.
pub struct HttpExchangeServer {
    addr: SocketAddr,
    tls: TlsIdentity,
    client_ca: Option<Vec<CertificateDer<'static>>>,
    config: HttpExchangeConfig,
}

impl HttpExchangeServer {
    pub fn new(addr: SocketAddr, tls: TlsIdentity) -> Self {
        Self {
            addr,
            tls,
            client_ca: None,
            config: HttpExchangeConfig::default(),
        }
    }

    pub fn with_config(mut self, config: HttpExchangeConfig) -> Self {
        self.config = config;
        self
    }

    /// Require mTLS client authentication validated against the coalition CA chain.
    pub fn with_client_ca(mut self, ca_pem: &[u8]) -> Result<Self, String> {
        let certs = rustls_pemfile::certs(&mut ca_pem.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        if certs.is_empty() {
            return Err("no client CA certificates in PEM".into());
        }
        self.client_ca = Some(certs);
        Ok(self)
    }

    pub async fn serve(self, broker: SecuredExchangeBroker) -> Result<(), String> {
        let config = build_server_config(&self.tls, self.client_ca.as_deref())?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(self.addr)
            .await
            .map_err(|e| e.to_string())?;

        let state = AppState {
            broker: Arc::new(tokio::sync::Mutex::new(broker)),
            trust_store: self.config.trust_store.clone(),
        };
        let app = Router::new()
            .route("/mip4-ies/v1/objects", post(put_object))
            .route("/health", get(|| async { "ok" }))
            .with_state(state);

        loop {
            let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let stream = match acceptor.accept(stream).await {
                    Ok(tls_stream) => tls_stream,
                    Err(_) => return,
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                let hyper_service =
                    hyper::service::service_fn(move |request| app.clone().call(request));
                if hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, hyper_service)
                    .await
                    .is_err()
                {
                    // Connection closed.
                }
            });
        }
    }
}

fn build_server_config(
    identity: &TlsIdentity,
    client_ca: Option<&[CertificateDer<'static>]>,
) -> Result<ServerConfig, String> {
    let certs: Vec<CertificateDer<'static>> = identity.cert_chain();
    let key = identity.private_key();
    if let Some(client_certs) = client_ca {
        let mut roots = RootCertStore::empty();
        for cert in client_certs {
            roots.add(cert.clone()).map_err(|e| e.to_string())?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| e.to_string())?;
        return ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| e.to_string());
    }
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())
}

#[derive(Clone)]
struct AppState {
    broker: Arc<tokio::sync::Mutex<SecuredExchangeBroker>>,
    trust_store: NmbTrustStore,
}

async fn put_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<RestEnvelope>,
) -> impl IntoResponse {
    match handle_put(&state, &headers, envelope).await {
        Ok(()) => (StatusCode::CREATED, "{\"created\":true}").into_response(),
        Err(err) => (StatusCode::FORBIDDEN, err.to_string()).into_response(),
    }
}

async fn handle_put(
    state: &AppState,
    headers: &HeaderMap,
    envelope: RestEnvelope,
) -> TransportResult<()> {
    let key_id = envelope
        .assertion
        .as_ref()
        .map(|a| a.signature.key_id.as_str())
        .ok_or_else(|| {
            mim_transport::TransportError::Forbidden(
                "REST envelope missing NMBS assertion".into(),
            )
        })?;
    let verifying_key = state
        .trust_store
        .verify_key_for(key_id)
        .map_err(|e| mim_transport::TransportError::Validation(e.to_string()))?
        .clone();
    if headers
        .get("X-NATO-Confidentiality-Label")
        .and_then(|v| v.to_str().ok())
        != Some(envelope.originator_confidentiality_label.as_str())
    {
        return Err(mim_transport::TransportError::Forbidden(
            "REST envelope label header mismatch".into(),
        ));
    }
    let request = unwrap_put_object(&envelope, &verifying_key)?;
    let mut broker = state.broker.lock().await;
    broker.put_object(request)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use mim_crypto::conformance_keypair;
    use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};
    use mim_stanag4778::RestEnvelope;
    use mim_transport::envelope::wrap_put_object;
    use mim_transport::message::PutObjectRequest;

    trait WithMetadata {
        fn with_metadata(self, metadata: mim_model::Metadata) -> Self;
    }

    impl WithMetadata for mim_runtime::MimInstance {
        fn with_metadata(mut self, metadata: mim_model::Metadata) -> Self {
            self.metadata = metadata;
            self
        }
    }

    #[test]
    fn tls_server_config_builds_from_fixture() {
        let identity = TlsIdentity::from_pem(
            include_bytes!("../fixtures/test-server.crt"),
            include_bytes!("../fixtures/test-server.key"),
        )
        .expect("tls identity");
        build_server_config(&identity, None).expect("server config");
    }

    #[test]
    fn handle_put_verifies_envelope_against_trust_store() {
        let keys = conformance_keypair().expect("keys");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let mut metadata = mim_model::Metadata::default();
        metadata.security.policy = mim_core::Nillable::value("NATO".into());
        metadata.security.classification = mim_core::Nillable::value("SECRET".into());
        metadata.security.releasability = mim_core::Nillable::value("USA".into());
        let instance = mim_runtime::MimInstance::new(
            "Target",
            mim_core::SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id"),
        )
        .expect("instance")
        .with_metadata(metadata);
        let envelope = wrap_put_object(
            &label,
            &PutObjectRequest { instance },
            keys.signing_key(),
        )
        .expect("wrap");
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-NATO-Confidentiality-Label",
            envelope
                .originator_confidentiality_label
                .parse()
                .expect("header"),
        );
        let state = AppState {
            broker: Arc::new(tokio::sync::Mutex::new(
                SecuredExchangeBroker::from_preset(
                    mim_transport::ExchangeBroker::new(test_registry()),
                    mim_policy::SubjectAttributes::new("analyst", ClassificationLevel::Secret),
                    "DOMAIN-HIGH",
                )
                .expect("broker"),
            )),
            trust_store: NmbTrustStore::from_verifying_keys([keys.verifying_key().clone()]),
        };
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(handle_put(&state, &headers, envelope)).expect("put");
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
                semantic_id: mim_core::SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
                parent: None,
                object_kind: Some(mim_model::ObjectKind::InformationResource),
                action_kind: None,
                definition: "Target".into(),
                package_path: "Classifiers::Object::InformationResource::Target".into(),
            }],
            elements: vec![ModelElementSpec {
                name: "Target".into(),
                kind: ModelElementKind::Class,
                semantic_id: mim_core::SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
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
}
