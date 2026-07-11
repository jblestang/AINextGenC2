use crate::error::{CryptoError, CryptoResult};
use crate::provider::selected_provider;

/// 256-bit content encryption key for ZTDF payload encryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentEncryptionKey {
    bytes: [u8; 32],
}

impl ContentEncryptionKey {
    pub fn generate() -> CryptoResult<Self> {
        selected_provider().generate_content_key()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// AES-256-GCM ciphertext with IV and authentication tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AesGcmCiphertext {
    pub iv: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

impl AesGcmCiphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.ciphertext.len() + 16);
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.tag);
        out
    }

    pub fn from_bytes(data: &[u8]) -> CryptoResult<Self> {
        if data.len() < 28 {
            return Err(CryptoError::Operation(
                "ciphertext too short for AES-256-GCM".into(),
            ));
        }
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&data[..12]);
        let tag_start = data.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[tag_start..]);
        let ciphertext = data[12..tag_start].to_vec();
        Ok(Self {
            iv,
            ciphertext,
            tag,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::keys::conformance_keypair;
    use crate::provider::selected_provider;

    #[test]
    fn aes_gcm_roundtrip() {
        let key = ContentEncryptionKey::generate().expect("cek");
        let plaintext = br#"{"modelVersion":"5.1.0"}"#;
        let aad = b"ztdf-payload";
        let provider = selected_provider();
        let encrypted = provider
            .encrypt_aes256_gcm(&key, plaintext, aad)
            .expect("encrypt");
        let decrypted = provider
            .decrypt_aes256_gcm(&key, &encrypted, aad)
            .expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rsa_key_wrap_roundtrip() {
        let kp = conformance_keypair().expect("keypair");
        let cek = ContentEncryptionKey::generate().expect("cek");
        let provider = selected_provider();
        let wrapped = provider
            .wrap_key_rsa_oaep_sha256(kp.verifying_key(), &cek)
            .expect("wrap");
        let unwrapped = provider
            .unwrap_key_rsa_oaep_sha256(kp.signing_key(), &wrapped)
            .expect("unwrap");
        assert_eq!(unwrapped, cek);
    }
}
