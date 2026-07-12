//! FIPS 140-3 validated cryptographic backend via AWS-LC (AES-GCM, SHA-256, RSA-PSS, RSA-OAEP).

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::digest::{digest, SHA256};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::rsa::{
    KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, OaepPublicEncryptingKey,
    PrivateDecryptingKey, PublicEncryptingKey,
};
use aws_lc_rs::signature::{self, KeyPair as RsaSigningKeyPair, RsaKeyPair, RSA_PSS_2048_8192_SHA256, RSA_PSS_SHA256};

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{KeyPair, SigningKey, VerifyingKey};
use crate::provider::CryptoProvider;
use crate::symmetric::{AesGcmCiphertext, ContentEncryptionKey};

pub struct FipsProvider;

impl CryptoProvider for FipsProvider {
    fn name(&self) -> &'static str {
        #[cfg(feature = "fips-validated")]
        {
            "aws-lc-rs (FIPS 140-3 validated, RSA inside boundary)"
        }
        #[cfg(all(feature = "fips", not(feature = "fips-validated")))]
        {
            "aws-lc-rs (FIPS-capable, RSA inside boundary)"
        }
        #[cfg(not(any(feature = "fips", feature = "fips-validated")))]
        {
            "aws-lc-rs (FIPS)"
        }
    }

    fn hash_sha256(&self, data: &[u8]) -> [u8; 32] {
        let digest = digest(&SHA256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }

    fn validate_signing_key(&self, pkcs8_der: &[u8]) -> CryptoResult<()> {
        RsaKeyPair::from_pkcs8(pkcs8_der)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
            .map(|_| ())
    }

    fn validate_verifying_key(&self, spki_der: &[u8]) -> CryptoResult<()> {
        PublicEncryptingKey::from_der(spki_der)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
            .map(|_| ())
    }

    fn generate_rsa_keypair(&self, key_id: &str) -> CryptoResult<KeyPair> {
        let key_pair = RsaKeyPair::generate(KeySize::Rsa2048)
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        let pkcs8 = key_pair
            .as_der()
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        KeyPair::from_pkcs8_der(key_id, pkcs8.as_ref())
    }

    fn public_key_from_private(&self, pkcs8_der: &[u8]) -> CryptoResult<Vec<u8>> {
        let key_pair = RsaKeyPair::from_pkcs8(pkcs8_der)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let public = RsaSigningKeyPair::public_key(&key_pair)
            .as_der()
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        Ok(public.as_ref().to_vec())
    }

    fn sign_rsa_pss_sha256(&self, key: &SigningKey, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let key_pair = RsaKeyPair::from_pkcs8(key.der())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; key_pair.public_modulus_len()];
        key_pair
            .sign(&RSA_PSS_SHA256, &rng, message, &mut signature)
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        Ok(signature)
    }

    fn verify_rsa_pss_sha256(
        &self,
        key: &VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> CryptoResult<()> {
        let public_key = signature::UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, key.der());
        public_key
            .verify(message, signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn wrap_key_rsa_oaep_sha256(
        &self,
        public_key: &VerifyingKey,
        content_key: &ContentEncryptionKey,
    ) -> CryptoResult<Vec<u8>> {
        let public = PublicEncryptingKey::from_der(public_key.der())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let oaep = OaepPublicEncryptingKey::new(public)
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        let mut ciphertext = vec![0u8; oaep.ciphertext_size()];
        let written = oaep
            .encrypt(
                &OAEP_SHA256_MGF1SHA256,
                content_key.as_bytes(),
                &mut ciphertext,
                None,
            )
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        Ok(written.to_vec())
    }

    fn unwrap_key_rsa_oaep_sha256(
        &self,
        private_key: &SigningKey,
        wrapped: &[u8],
    ) -> CryptoResult<ContentEncryptionKey> {
        let private = PrivateDecryptingKey::from_pkcs8(private_key.der())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let oaep = OaepPrivateDecryptingKey::new(private)
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        let mut plaintext = vec![0u8; oaep.min_output_size()];
        let written = oaep
            .decrypt(&OAEP_SHA256_MGF1SHA256, wrapped, &mut plaintext, None)
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        if written.len() != 32 {
            return Err(CryptoError::Operation(
                "unwrapped key length is not 256 bits".into(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(written);
        Ok(ContentEncryptionKey::from_bytes(key))
    }

    fn encrypt_aes256_gcm(
        &self,
        key: &ContentEncryptionKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<AesGcmCiphertext> {
        let unbound = UnboundKey::new(&AES_256_GCM, key.as_bytes())
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        let sealing = LessSafeKey::new(unbound);
        let mut iv = [0u8; 12];
        self.fill_random(&mut iv)?;
        let nonce = Nonce::assume_unique_for_key(iv);
        let mut in_out = plaintext.to_vec();
        sealing
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        let tag_start = in_out.len().saturating_sub(16);
        let mut tag = [0u8; 16];
        let tag_slice = in_out
            .get(tag_start..)
            .ok_or_else(|| CryptoError::Operation("AES-GCM tag missing".into()))?;
        tag.copy_from_slice(tag_slice);
        in_out.truncate(tag_start);
        Ok(AesGcmCiphertext {
            iv,
            ciphertext: in_out,
            tag,
        })
    }

    fn decrypt_aes256_gcm(
        &self,
        key: &ContentEncryptionKey,
        ciphertext: &AesGcmCiphertext,
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let unbound = UnboundKey::new(&AES_256_GCM, key.as_bytes())
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        let opening = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(ciphertext.iv);
        let mut in_out = ciphertext.ciphertext.clone();
        in_out.extend_from_slice(&ciphertext.tag);
        let plain = opening
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(plain.to_vec())
    }

    fn fill_random(&self, buf: &mut [u8]) -> CryptoResult<()> {
        SystemRandom::new()
            .fill(buf)
            .map_err(|e| CryptoError::Operation(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use crate::provider::{sign_nmb_binding, verify_nmb_binding};

    use super::*;

    #[test]
    fn fips_rsa_pss_round_trip() {
        let provider = FipsProvider;
        let key_pair = provider
            .generate_rsa_keypair("fips-test")
            .expect("generate");
        let message = b"label|digest";
        let signature = provider
            .sign_rsa_pss_sha256(key_pair.signing_key(), message)
            .expect("sign");
        provider
            .verify_rsa_pss_sha256(key_pair.verifying_key(), message, &signature)
            .expect("verify");
    }

    #[test]
    fn fips_rsa_oaep_round_trip() {
        let provider = FipsProvider;
        let key_pair = provider
            .generate_rsa_keypair("fips-wrap")
            .expect("generate");
        let cek = ContentEncryptionKey::from_bytes([7u8; 32]);
        let wrapped = provider
            .wrap_key_rsa_oaep_sha256(key_pair.verifying_key(), &cek)
            .expect("wrap");
        let unwrapped = provider
            .unwrap_key_rsa_oaep_sha256(key_pair.signing_key(), &wrapped)
            .expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), cek.as_bytes());
    }

    #[test]
    fn nmb_binding_uses_fips_rsa() {
        let provider = FipsProvider;
        let key_pair = provider.generate_rsa_keypair("nmb").expect("generate");
        let sig = sign_nmb_binding(key_pair.signing_key(), b"label-xml", "digest")
            .expect("sign");
        verify_nmb_binding(key_pair.verifying_key(), b"label-xml", "digest", &sig).expect("verify");
    }
}
