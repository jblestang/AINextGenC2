//! Production PKI loading for NMBS signing and ZTDF key-wrapping keys.

use std::fs;
use std::path::Path;

use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{KeyPair, SigningKey, VerifyingKey};

/// Coalition NMBS / KAS key ring loaded from PEM material on disk or in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NmbKeyRing {
    pub nmb: KeyPair,
    pub kas: KeyPair,
}

impl NmbKeyRing {
    /// Load NMBS and KAS key pairs from PKCS#8 private key PEM files.
    pub fn from_pkcs8_files(
        nmb_private_pem: impl AsRef<Path>,
        kas_private_pem: impl AsRef<Path>,
        nmb_key_id: impl Into<String>,
        kas_key_id: impl Into<String>,
    ) -> CryptoResult<Self> {
        let nmb_der = load_pkcs8_der(nmb_private_pem)?;
        let kas_der = load_pkcs8_der(kas_private_pem)?;
        Ok(Self {
            nmb: KeyPair::from_pkcs8_der(nmb_key_id, &nmb_der)?,
            kas: KeyPair::from_pkcs8_der(kas_key_id, &kas_der)?,
        })
    }

    /// Load from in-memory PEM bytes (embedded fixtures, HSM export, etc.).
    pub fn from_pkcs8_pem(
        nmb_private_pem: &[u8],
        kas_private_pem: &[u8],
        nmb_key_id: impl Into<String>,
        kas_key_id: impl Into<String>,
    ) -> CryptoResult<Self> {
        let nmb_der = decode_pkcs8_pem(nmb_private_pem)?;
        let kas_der = decode_pkcs8_pem(kas_private_pem)?;
        Ok(Self {
            nmb: KeyPair::from_pkcs8_der(nmb_key_id, &nmb_der)?,
            kas: KeyPair::from_pkcs8_der(kas_key_id, &kas_der)?,
        })
    }

    /// Conformance / lab key ring (deterministic RSA fixture).
    pub fn conformance() -> CryptoResult<Self> {
        let kp = crate::keys::conformance_keypair()?;
        Ok(Self {
            nmb: kp.clone(),
            kas: kp,
        })
    }

    pub fn nmb_signing(&self) -> &SigningKey {
        self.nmb.signing_key()
    }

    pub fn nmb_verifying(&self) -> &VerifyingKey {
        self.nmb.verifying_key()
    }

    pub fn kas_signing(&self) -> &SigningKey {
        self.kas.signing_key()
    }

    pub fn kas_verifying(&self) -> &VerifyingKey {
        self.kas.verifying_key()
    }
}

/// Trust anchor for verifying inbound NMBS REST/ZTDF bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NmbTrustStore {
    keys: Vec<VerifyingKey>,
}

impl NmbTrustStore {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn add_verifying_key(mut self, key: VerifyingKey) -> Self {
        self.keys.push(key);
        self
    }

    pub fn from_verifying_keys(keys: impl IntoIterator<Item = VerifyingKey>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }

    /// Load SPKI public keys from PEM files (`BEGIN PUBLIC KEY` blocks).
    pub fn from_spki_pem_files(
        paths: impl IntoIterator<Item = impl AsRef<Path>>,
    ) -> CryptoResult<Self> {
        let mut keys = Vec::new();
        for path in paths {
            let pem = fs::read(path.as_ref())
                .map_err(|e| CryptoError::InvalidKey(format!("read SPKI PEM: {e}")))?;
            keys.extend(load_spki_ders_from_pem(&pem)?);
        }
        Self::from_spki_ders(keys)
    }

    pub fn from_spki_pem(pem: &[u8], key_id_prefix: &str) -> CryptoResult<Self> {
        Self::from_spki_ders_with_prefix(load_spki_ders_from_pem(pem)?, key_id_prefix)
    }

    pub fn from_spki_der(key_id: impl Into<String>, der: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            keys: vec![VerifyingKey::from_spki_der(key_id, der)?],
        })
    }

    fn from_spki_ders(ders: Vec<Vec<u8>>) -> CryptoResult<Self> {
        Self::from_spki_ders_with_prefix(ders, "nmb-trust")
    }

    fn from_spki_ders_with_prefix(ders: Vec<Vec<u8>>, key_id_prefix: &str) -> CryptoResult<Self> {
        if ders.is_empty() {
            return Err(CryptoError::InvalidKey("no verifying keys loaded".into()));
        }
        let keys = ders
            .into_iter()
            .enumerate()
            .map(|(idx, der)| VerifyingKey::from_spki_der(format!("{key_id_prefix}-{idx}"), &der))
            .collect::<CryptoResult<Vec<_>>>()?;
        Ok(Self { keys })
    }

    pub fn verify_key_for(&self, key_id: &str) -> CryptoResult<&VerifyingKey> {
        self.keys
            .iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| {
                CryptoError::InvalidKey(format!("unknown NMBS verifying key id: {key_id}"))
            })
    }

    pub fn primary(&self) -> CryptoResult<&VerifyingKey> {
        self.keys
            .first()
            .ok_or_else(|| CryptoError::InvalidKey("trust store is empty".into()))
    }

    pub fn keys(&self) -> &[VerifyingKey] {
        &self.keys
    }
}

impl Default for NmbTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

fn load_pkcs8_der(path: impl AsRef<Path>) -> CryptoResult<Vec<u8>> {
    let pem = fs::read(path.as_ref())
        .map_err(|e| CryptoError::InvalidKey(format!("read PKCS#8: {e}")))?;
    decode_pkcs8_pem(&pem)
}

fn decode_pkcs8_pem(pem: &[u8]) -> CryptoResult<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem)
        .map_err(|e| CryptoError::InvalidKey(format!("PKCS#8 PEM is not UTF-8: {e}")))?;
    let private = RsaPrivateKey::from_pkcs8_pem(pem_str)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    private
        .to_pkcs8_der()
        .map(|der| der.as_bytes().to_vec())
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))
}

fn load_spki_ders_from_pem(pem: &[u8]) -> CryptoResult<Vec<Vec<u8>>> {
    let pem_str = std::str::from_utf8(pem)
        .map_err(|e| CryptoError::InvalidKey(format!("SPKI PEM is not UTF-8: {e}")))?;
    let mut keys = Vec::new();
    for block in pem_str.split("-----BEGIN PUBLIC KEY-----").skip(1) {
        let body = block
            .split("-----END PUBLIC KEY-----")
            .next()
            .unwrap_or(block);
        let wrapped = format!("-----BEGIN PUBLIC KEY-----{body}-----END PUBLIC KEY-----");
        let public = RsaPublicKey::from_public_key_pem(&wrapped)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let der = public
            .to_public_key_der()
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        keys.push(der.as_bytes().to_vec());
    }
    Ok(keys)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn conformance_key_ring_loads() {
        let ring = NmbKeyRing::conformance().expect("ring");
        assert_eq!(ring.nmb.signing.key_id, "nmb-conformance-key-1");
    }

    #[test]
    fn trust_store_from_conformance_spki_der() {
        let der = include_bytes!("../fixtures/nmb-conformance-rsa.spki");
        let store = NmbTrustStore::from_spki_der("nmb-conformance-key-1", der).expect("store");
        assert_eq!(store.primary().expect("primary").key_id, "nmb-conformance-key-1");
    }
}
