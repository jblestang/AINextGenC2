//! mTLS peer identity extraction and request-scoped subject resolution.

use axum::http::HeaderMap;
use mim_policy::{PolicyError, SubjectAttributes, SubjectResolver};
use x509_parser::oid_registry;
use x509_parser::prelude::*;

/// Request extension carrying the authenticated TLS client identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsClientIdentity {
    pub cn: String,
    pub cert_sha256: Option<String>,
    pub subject_dn: Option<String>,
}

/// HTTP header used in lab mode when mTLS identity is injected by a reverse proxy.
pub const HEADER_MIM_CLIENT_CN: &str = "X-MIM-Client-CN";

/// HTTP header carrying a full LDAP principal when CN mapping is insufficient.
pub const HEADER_MIM_CLIENT_PRINCIPAL: &str = "X-MIM-Client-Principal";

/// HTTP header carrying the SHA-256 fingerprint of the client certificate (hex).
pub const HEADER_MIM_CLIENT_CERT_SHA256: &str = "X-MIM-Client-Cert-Sha256";

/// Extract the subject CN from a DER-encoded X.509 certificate.
pub fn client_cn_from_cert_der(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type().eq(&oid_registry::OID_X509_COMMON_NAME) {
                if let Ok(cn) = attr.as_str() {
                    return Some(cn.to_owned());
                }
            }
        }
    }
    None
}

/// Extract the full subject DN string from a DER-encoded X.509 certificate.
pub fn client_subject_dn_from_cert_der(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    Some(cert.subject().to_string())
}

/// Resolve the request subject from mTLS identity headers and the LDAP directory.
pub fn resolve_request_subject(
    resolver: &SubjectResolver,
    headers: &HeaderMap,
    tls_identity: Option<&TlsClientIdentity>,
    require_identity: bool,
) -> Result<SubjectAttributes, PolicyError> {
    if let Some(principal) = headers
        .get(HEADER_MIM_CLIENT_PRINCIPAL)
        .and_then(|value| value.to_str().ok())
    {
        return resolver.resolve(principal);
    }
    if let Some(fingerprint) = headers
        .get(HEADER_MIM_CLIENT_CERT_SHA256)
        .and_then(|value| value.to_str().ok())
    {
        return resolver.resolve_cert_fingerprint(fingerprint);
    }
    if let Some(cn) = headers
        .get(HEADER_MIM_CLIENT_CN)
        .and_then(|value| value.to_str().ok())
    {
        return resolver.resolve(cn);
    }
    if let Some(identity) = tls_identity {
        if let Some(fingerprint) = &identity.cert_sha256 {
            if let Ok(subject) = resolver.resolve_cert_fingerprint(fingerprint) {
                return Ok(subject);
            }
        }
        return resolver.resolve(&identity.cn);
    }
    if require_identity {
        return Err(PolicyError::Denied(
            "mTLS client identity required for PEP-gated access".into(),
        ));
    }
    Err(PolicyError::NotFound(
        "no client identity in request (mTLS cert fingerprint, CN, or X-MIM-Client-CN header)".into(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use mim_policy::SubjectResolver;

    #[test]
    fn extracts_cn_from_fixture_server_cert() {
        let pem = include_bytes!("../fixtures/test-server.crt");
        let cert_der = rustls_pemfile::certs(&mut pem.as_ref())
            .next()
            .expect("cert")
            .expect("parse");
        let cn = client_cn_from_cert_der(cert_der.as_ref()).expect("cn");
        assert!(!cn.is_empty());
        assert!(client_subject_dn_from_cert_der(cert_der.as_ref()).is_some());
    }

    #[test]
    fn resolves_subject_from_client_cn_header() {
        let resolver = SubjectResolver::conformance().expect("resolver");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_MIM_CLIENT_CN,
            "gbr-analyst.nato.mil".parse().expect("header"),
        );
        let subject = resolve_request_subject(&resolver, &headers, None, false).expect("subject");
        assert_eq!(subject.subject_id, "gbr-analyst");
    }
}
