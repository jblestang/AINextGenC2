use crate::error::CryptoResult;
use crate::provider::selected_provider;

/// NMBS signing key (RSA private key, PKCS#8 DER).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKey {
    pub key_id: String,
    der: Vec<u8>,
}

impl SigningKey {
    pub fn from_pkcs8_der(key_id: impl Into<String>, der: &[u8]) -> CryptoResult<Self> {
        selected_provider().validate_signing_key(der)?;
        Ok(Self {
            key_id: key_id.into(),
            der: der.to_vec(),
        })
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

/// NMBS verifying key (RSA public key, SPKI DER).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub key_id: String,
    der: Vec<u8>,
}

impl VerifyingKey {
    pub fn from_spki_der(key_id: impl Into<String>, der: &[u8]) -> CryptoResult<Self> {
        selected_provider().validate_verifying_key(der)?;
        Ok(Self {
            key_id: key_id.into(),
            der: der.to_vec(),
        })
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

/// Public alias for verifying keys in key-wrap contexts.
pub type PublicKey = VerifyingKey;

/// RSA key pair for NMBS binding and ZTDF key wrapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub signing: SigningKey,
    pub verifying: VerifyingKey,
}

impl KeyPair {
    pub fn generate(key_id: impl Into<String>) -> CryptoResult<KeyPair> {
        selected_provider().generate_rsa_keypair(&key_id.into())
    }

    pub fn from_pkcs8_der(key_id: impl Into<String>, private_der: &[u8]) -> CryptoResult<KeyPair> {
        let key_id = key_id.into();
        let signing = SigningKey::from_pkcs8_der(&key_id, private_der)?;
        let public_der = selected_provider().public_key_from_private(private_der)?;
        let verifying = VerifyingKey::from_spki_der(key_id, &public_der)?;
        Ok(Self { signing, verifying })
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

/// Conformance / test NMBS key pair (2048-bit RSA, deterministic fixture).
pub fn conformance_keypair() -> CryptoResult<KeyPair> {
    KeyPair::from_pkcs8_der("nmb-conformance-key-1", CONFORMANCE_PRIVATE_KEY_DER)
}

const CONFORMANCE_PRIVATE_KEY_DER: &[u8] = include_bytes!("../fixtures/nmb-conformance-rsa.pk8");

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::provider::{sign_nmb_binding, verify_nmb_binding};

    #[test]
    fn conformance_keypair_loads() {
        let kp = conformance_keypair().expect("keypair");
        assert_eq!(kp.signing.key_id, "nmb-conformance-key-1");
    }

    #[test]
    fn generated_keypair_roundtrip() {
        let kp = KeyPair::generate("generated").expect("generate");
        assert_eq!(kp.signing.key_id, "generated");
    }

    #[test]
    fn sign_verify_roundtrip_with_conformance_key() {
        let kp = conformance_keypair().expect("keypair");
        let sig = sign_nmb_binding(kp.signing_key(), b"label", "digest")
            .expect("sign");
        verify_nmb_binding(kp.verifying_key(), b"label", "digest", &sig).expect("verify");
    }
}
