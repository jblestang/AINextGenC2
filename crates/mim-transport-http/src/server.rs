//! TLS/mTLS MIP4-IES HTTP server with STANAG 4778 REST envelope verification.

use std::net::SocketAddr;
use std::sync::Arc;

use mim_crypto::NmbTrustStore;
use mim_crypto::PkiMode;
use mim_policy::{SubjectAttributes, SubjectResolver};
use mim_transport::FederationConfig;
use mim_transport::secured::SecuredExchangeBroker;
use rustls::pki_types::CertificateDer;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio::sync::Mutex;
use tower::Service;

use crate::identity::{
    client_cn_from_cert_der, client_subject_dn_from_cert_der, TlsClientIdentity,
    HEADER_MIM_CLIENT_CERT_SHA256,
};
use crate::routes::{self, AppState};
use crate::tls::TlsIdentity;

/// Runtime configuration for HTTPS exchange verification and PKI trust.
#[derive(Clone, Debug)]
pub struct HttpExchangeConfig {
    pub trust_store: NmbTrustStore,
    pub subject_resolver: SubjectResolver,
    pub require_client_identity: bool,
    pub fallback_subject: Option<SubjectAttributes>,
}

impl HttpExchangeConfig {
    /// Lab/conformance trust store and subject resolver (no environment variables).
    pub fn lab() -> mim_crypto::CryptoResult<Self> {
        Self::conformance()
    }

    pub fn conformance() -> mim_crypto::CryptoResult<Self> {
        let kp = mim_crypto::conformance_keypair()?;
        Ok(Self {
            trust_store: NmbTrustStore::from_verifying_keys([kp.verifying_key().clone()]),
            subject_resolver: SubjectResolver::conformance()
                .map_err(|e| mim_crypto::CryptoError::Operation(e.to_string()))?,
            require_client_identity: false,
            fallback_subject: Some(SubjectAttributes::new(
                "analyst",
                mim_labeling::ClassificationLevel::Secret,
            )),
        })
    }

    /// Coalition exercise: identity required, no fallback subject (FMN mTLS/LDAP PIP).
    pub fn coalition_exercise(
        mode: PkiMode,
        ldap_config_path: Option<&str>,
    ) -> mim_crypto::CryptoResult<Self> {
        if let Some(path) = ldap_config_path {
            std::env::set_var("MIM_LDAP_PIP_CONFIG", path);
        }
        let subject_resolver = SubjectResolver::from_env()
            .or_else(|_| SubjectResolver::conformance())
            .map_err(|e| mim_crypto::CryptoError::Operation(e.to_string()))?;
        Ok(Self {
            trust_store: mim_crypto::load_trust_store_for(mode)?,
            subject_resolver,
            require_client_identity: true,
            fallback_subject: None,
        })
    }

    /// Production trust store from `MIM_NMB_TRUST`.
    pub fn production() -> mim_crypto::CryptoResult<Self> {
        Self::for_mode(PkiMode::Production)
    }

    pub fn for_mode(mode: PkiMode) -> mim_crypto::CryptoResult<Self> {
        let federation = FederationConfig::from_env().ok();
        let subject_resolver = SubjectResolver::from_env()
            .or_else(|_| SubjectResolver::conformance())
            .map_err(|e| mim_crypto::CryptoError::Operation(e.to_string()))?;
        let require_client_identity = federation
            .as_ref()
            .map(FederationConfig::require_mtls)
            .unwrap_or_else(|| {
                std::env::var("MIM_REQUIRE_CLIENT_IDENTITY")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
            });
        Ok(Self {
            trust_store: mim_crypto::load_trust_store_for(mode)?,
            subject_resolver,
            require_client_identity,
            fallback_subject: None,
        })
    }

    /// Production trust store from `MIM_NMB_TRUST`.
    pub fn from_env() -> mim_crypto::CryptoResult<Self> {
        Self::for_mode(PkiMode::Production)
    }
}

impl Default for HttpExchangeConfig {
    fn default() -> Self {
        Self::lab().expect("lab HTTP exchange config")
    }
}

/// MIP4-IES exchange server over HTTPS with STANAG 4778 REST envelopes.
pub struct HttpExchangeServer {
    addr: SocketAddr,
    tls: TlsIdentity,
    client_ca: Option<Vec<CertificateDer<'static>>>,
    config: HttpExchangeConfig,
    webhook_targets: Vec<String>,
    federation_pull_url: Option<String>,
    federation_client_cn: Option<String>,
    federation_pki_mode: PkiMode,
}

impl HttpExchangeServer {
    pub fn new(addr: SocketAddr, tls: TlsIdentity) -> Self {
        Self {
            addr,
            tls,
            client_ca: None,
            config: HttpExchangeConfig::default(),
            webhook_targets: Vec::new(),
            federation_pull_url: None,
            federation_client_cn: None,
            federation_pki_mode: PkiMode::Lab,
        }
    }

    /// Configure coalition federation webhooks (and production PKI/mTLS when `mode` is production).
    pub fn with_federation(
        mut self,
        federation: &FederationConfig,
        mode: PkiMode,
    ) -> Result<Self, String> {
        self.federation_pki_mode = mode;
        if mode == PkiMode::Production {
            federation.apply_pki_env().map_err(|e| e.to_string())?;
            if let Some(ca_path) = federation.client_ca_path() {
                let pem = std::fs::read(ca_path)
                    .map_err(|e| format!("read client CA {}: {e}", ca_path))?;
                self = self.with_client_ca(&pem)?;
            }
        }
        if let Some(url) = federation.peer_notify_url("gbr") {
            self.webhook_targets = vec![url.to_owned()];
        }
        Ok(self)
    }

    /// Lab federation wiring: webhook targets only (no production PKI env or mTLS CA).
    pub fn with_federation_lab(mut self, federation: &FederationConfig) -> Self {
        self.federation_pki_mode = PkiMode::Lab;
        if let Some(url) = federation.peer_notify_url("gbr") {
            self.webhook_targets = vec![url.to_owned()];
        }
        self
    }

    pub fn with_federation_pull(
        mut self,
        publisher_sync_url: impl Into<String>,
        client_cn: impl Into<String>,
    ) -> Self {
        self.federation_pull_url = Some(publisher_sync_url.into());
        self.federation_client_cn = Some(client_cn.into());
        self
    }

    pub fn with_webhook_targets(mut self, targets: Vec<String>) -> Self {
        self.webhook_targets = targets;
        self
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
        let listener = TcpListener::bind(self.addr)
            .await
            .map_err(|e| e.to_string())?;
        let (acceptor, app) = self.build_runtime(broker)?;
        accept_loop(listener, acceptor, app).await
    }

    /// Start HTTPS server on an ephemeral port; returns bound address and background task.
    pub async fn serve_ephemeral(
        self,
        broker: SecuredExchangeBroker,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), String> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|e| e.to_string())?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let (acceptor, app) = self.build_runtime(broker)?;
        let handle = tokio::spawn(async move {
            let _ = accept_loop(listener, acceptor, app).await;
        });
        Ok((addr, handle))
    }

    fn build_runtime(
        self,
        broker: SecuredExchangeBroker,
    ) -> Result<(TlsAcceptor, axum::Router), String> {
        let config = build_server_config(&self.tls, self.client_ca.as_deref())?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let state = AppState {
            broker: Arc::new(Mutex::new(broker)),
            trust_store: self.config.trust_store.clone(),
            subject_resolver: Arc::new(self.config.subject_resolver.clone()),
            require_client_identity: self.config.require_client_identity,
            fallback_subject: self.config.fallback_subject.clone(),
            webhook_targets: Arc::new(self.webhook_targets.clone()),
            federation_pull_url: self.federation_pull_url.clone(),
            federation_client_cn: self.federation_client_cn.clone(),
            federation_pki_mode: self.federation_pki_mode,
        };
        Ok((acceptor, routes::exchange_router(state)))
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: axum::Router,
) -> Result<(), String> {
    loop {
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(_) => return,
            };
            let peer_identity = extract_peer_identity(&stream);
            let io = hyper_util::rt::TokioIo::new(stream);
            let hyper_service = hyper::service::service_fn(move |mut request| {
                let mut app = app.clone();
                let peer_identity = peer_identity.clone();
                async move {
                    if let Some(identity) = &peer_identity {
                        if let Ok(value) = axum::http::HeaderValue::from_str(&identity.cn) {
                            request
                                .headers_mut()
                                .insert("X-MIM-Tls-Client-CN", value);
                        }
                        if let Some(fingerprint) = &identity.cert_sha256 {
                            if let Ok(value) = axum::http::HeaderValue::from_str(fingerprint) {
                                request.headers_mut().insert(
                                    HEADER_MIM_CLIENT_CERT_SHA256,
                                    value,
                                );
                            }
                        }
                        if let Some(dn) = &identity.subject_dn {
                            if let Ok(value) = axum::http::HeaderValue::from_str(dn) {
                                request
                                    .headers_mut()
                                    .insert("X-MIM-Tls-Client-DN", value);
                            }
                        }
                    }
                    app.call(request).await
                }
            });
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

fn extract_peer_identity<S>(tls: &tokio_rustls::server::TlsStream<S>) -> Option<TlsClientIdentity> {
    let (_io, conn) = tls.get_ref();
    let cert = conn.peer_certificates()?.first()?;
    let cert_der = cert.as_ref();
    let cert_sha256 = mim_crypto::sha256_hex(cert_der);
    let cn = client_cn_from_cert_der(cert_der)
        .unwrap_or_else(|| format!("cert-{cert_sha256}"));
    let subject_dn = client_subject_dn_from_cert_der(cert_der);
    Some(TlsClientIdentity {
        cn,
        cert_sha256: Some(cert_sha256),
        subject_dn,
    })
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use mim_crypto::conformance_keypair;
    use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};
    use mim_model::Metadata;
    use mim_runtime::MimInstance;
    use mim_transport::envelope::wrap_put_object;
    use mim_transport::message::PutObjectRequest;

    trait WithMetadata {
        fn with_metadata(self, metadata: Metadata) -> Self;
    }

    impl WithMetadata for MimInstance {
        fn with_metadata(mut self, metadata: Metadata) -> Self {
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

    #[tokio::test]
    async fn handle_put_verifies_envelope_against_trust_store() {
        let keys = conformance_keypair().expect("keys");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let mut metadata = Metadata::default();
        metadata.security.policy = mim_core::Nillable::value("NATO".into());
        metadata.security.classification = mim_core::Nillable::value("SECRET".into());
        metadata.security.releasability = mim_core::Nillable::value("USA".into());
        let instance = MimInstance::new(
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
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "X-NATO-Confidentiality-Label",
            envelope
                .originator_confidentiality_label
                .parse()
                .expect("header"),
        );
        let state = AppState {
            broker: Arc::new(Mutex::new(
                SecuredExchangeBroker::from_preset(
                    mim_transport::ExchangeBroker::new(test_registry()),
                    mim_policy::SubjectAttributes::new("analyst", ClassificationLevel::Secret),
                    "DOMAIN-HIGH",
                )
                .expect("broker"),
            )),
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
        };
        routes::handle_put(&state, &headers, None, envelope)
            .await
            .expect("put");
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
