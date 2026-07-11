use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{KeyPair, SigningKey, VerifyingKey};
use crate::symmetric::{AesGcmCiphertext, ContentEncryptionKey};

/// NMBS digital signature algorithm per ADatP-4778.
pub const NMBS_ALGORITHM: &str = "RSA-PSS-SHA256";
pub const NMBS_ALGORITHM_URI: &str = "urn:nato:stanag:4778:binding:rsa-pss-sha256";

/// Cryptographic backend for NMBS signatures, hashing, and ZTDF encryption.
pub trait CryptoProvider: Send + Sync {
    fn name(&self) -> &'static str;

    fn hash_sha256(&self, data: &[u8]) -> [u8; 32];

    fn validate_signing_key(&self, pkcs8_der: &[u8]) -> CryptoResult<()>;
    fn validate_verifying_key(&self, spki_der: &[u8]) -> CryptoResult<()>;

    fn generate_rsa_keypair(&self, key_id: &str) -> CryptoResult<KeyPair>;
    fn public_key_from_private(&self, pkcs8_der: &[u8]) -> CryptoResult<Vec<u8>>;

    fn fill_random(&self, buf: &mut [u8]) -> CryptoResult<()>;

    fn generate_content_key(&self) -> CryptoResult<ContentEncryptionKey> {
        let mut bytes = [0u8; 32];
        self.fill_random(&mut bytes)?;
        Ok(ContentEncryptionKey::from_bytes(bytes))
    }

    /// NMBS Set: RSA-PSS-SHA256 signature over `message`.
    fn sign_rsa_pss_sha256(&self, key: &SigningKey, message: &[u8]) -> CryptoResult<Vec<u8>>;

    /// NMBS Verify: RSA-PSS-SHA256 signature verification.
    fn verify_rsa_pss_sha256(
        &self,
        key: &VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> CryptoResult<()>;

    /// RSA-OAEP-SHA256 key wrap (ZTDF content key wrapping).
    fn wrap_key_rsa_oaep_sha256(
        &self,
        public_key: &VerifyingKey,
        content_key: &ContentEncryptionKey,
    ) -> CryptoResult<Vec<u8>>;

    fn unwrap_key_rsa_oaep_sha256(
        &self,
        private_key: &SigningKey,
        wrapped: &[u8],
    ) -> CryptoResult<ContentEncryptionKey>;

    /// AES-256-GCM encrypt (ZTDF payload encryption).
    fn encrypt_aes256_gcm(
        &self,
        key: &ContentEncryptionKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<AesGcmCiphertext>;

    fn decrypt_aes256_gcm(
        &self,
        key: &ContentEncryptionKey,
        ciphertext: &AesGcmCiphertext,
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>>;
}

/// Active provider for this build (FIPS AWS-LC by default, `ring` when `ring-backend` only).
pub enum ActiveProvider {
    #[cfg(all(feature = "ring-backend", not(any(feature = "fips", feature = "fips-validated"))))]
    Ring,
    #[cfg(any(feature = "fips", feature = "fips-validated"))]
    Fips,
}

impl ActiveProvider {
    pub fn get(&self) -> &'static dyn CryptoProvider {
        match self {
            #[cfg(all(feature = "ring-backend", not(any(feature = "fips", feature = "fips-validated"))))]
            Self::Ring => &crate::ring_backend::RingProvider,
            #[cfg(any(feature = "fips", feature = "fips-validated"))]
            Self::Fips => &crate::fips_backend::FipsProvider,
        }
    }
}

/// Returns the active cryptographic provider for this build configuration.
pub fn selected_provider() -> &'static dyn CryptoProvider {
    #[cfg(any(feature = "fips", feature = "fips-validated"))]
    {
        return ActiveProvider::Fips.get();
    }
    #[cfg(all(feature = "ring-backend", not(any(feature = "fips", feature = "fips-validated"))))]
    {
        return ActiveProvider::Ring.get();
    }
    #[cfg(not(any(feature = "fips", feature = "fips-validated", feature = "ring-backend")))]
    compile_error!("enable `fips` / `fips-validated` (default) or `ring-backend` feature");
}

/// Sign NMBS binding material: canonical label bytes + delimiter + payload digest.
pub fn sign_nmb_binding(
    key: &SigningKey,
    label_bytes: &[u8],
    payload_digest_b64: &str,
) -> CryptoResult<String> {
    let mut message = Vec::with_capacity(label_bytes.len() + 1 + payload_digest_b64.len());
    message.extend_from_slice(label_bytes);
    message.push(b'|');
    message.extend_from_slice(payload_digest_b64.as_bytes());
    let sig = selected_provider().sign_rsa_pss_sha256(key, &message)?;
    Ok(STANDARD.encode(sig))
}

/// Verify NMBS binding signature.
pub fn verify_nmb_binding(
    key: &VerifyingKey,
    label_bytes: &[u8],
    payload_digest_b64: &str,
    signature_b64: &str,
) -> CryptoResult<()> {
    let mut message = Vec::with_capacity(label_bytes.len() + 1 + payload_digest_b64.len());
    message.extend_from_slice(label_bytes);
    message.push(b'|');
    message.extend_from_slice(payload_digest_b64.as_bytes());
    let sig = STANDARD
        .decode(signature_b64)
        .map_err(|e| CryptoError::Operation(e.to_string()))?;
    selected_provider().verify_rsa_pss_sha256(key, &message, &sig)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::hash::sha256_base64;
    use crate::keys::conformance_keypair;

    #[test]
    fn nmb_binding_sign_verify() {
        let kp = conformance_keypair().expect("keypair");
        let label = b"<ConfidentialityLabel/>";
        let digest = sha256_base64(b"payload");
        let sig = sign_nmb_binding(kp.signing_key(), label, &digest).expect("sign");
        verify_nmb_binding(kp.verifying_key(), label, &digest, &sig).expect("verify");
    }
}
