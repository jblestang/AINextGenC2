use std::fs;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};

/// TLS identity for MIP4-IES HTTPS/mTLS binding.
pub struct TlsIdentity {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl Clone for TlsIdentity {
    fn clone(&self) -> Self {
        Self {
            cert_chain: self.cert_chain.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

impl TlsIdentity {
    pub fn from_pem_files(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self, String> {
        let cert_pem = fs::read(cert_path).map_err(|e| e.to_string())?;
        let key_pem = fs::read(key_path).map_err(|e| e.to_string())?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, String> {
        let cert_chain = certs(&mut cert_pem.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let mut keys = pkcs8_private_keys(&mut key_pem.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let private_key = keys
            .pop()
            .ok_or_else(|| "no private key in PEM".to_string())?;
        Ok(Self {
            cert_chain,
            private_key: PrivateKeyDer::Pkcs8(private_key),
        })
    }

    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        self.cert_chain.clone()
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        self.private_key.clone_key()
    }
}

/// TLS server configuration for coalition MIP4-IES exchange.
#[derive(Clone)]
pub struct TlsConfig {
    identity: Arc<TlsIdentity>,
}

impl TlsConfig {
    pub fn new(identity: TlsIdentity) -> Self {
        Self {
            identity: Arc::new(identity),
        }
    }

    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        self.identity.cert_chain()
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        self.identity.private_key()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn loads_generated_test_certs() {
        let cert = include_str!("../fixtures/test-server.crt");
        let key = include_str!("../fixtures/test-server.key");
        let identity = TlsIdentity::from_pem(cert.as_bytes(), key.as_bytes()).expect("identity");
        assert!(!identity.cert_chain().is_empty());
    }
}
