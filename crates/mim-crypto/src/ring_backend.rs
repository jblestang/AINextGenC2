use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::pss::{Signature, SigningKey as PssSigningKey, VerifyingKey as PssVerifyingKey};
use rsa::{Oaep, PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{KeyPair, SigningKey, VerifyingKey};
use crate::provider::CryptoProvider;
use crate::symmetric::{AesGcmCiphertext, ContentEncryptionKey};

pub struct RingProvider;

impl CryptoProvider for RingProvider {
    fn name(&self) -> &'static str {
        "ring"
    }

    fn hash_sha256(&self, data: &[u8]) -> [u8; 32] {
        let digest = digest(&SHA256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }

    fn validate_signing_key(&self, pkcs8_der: &[u8]) -> CryptoResult<()> {
        RsaPrivateKey::from_pkcs8_der(pkcs8_der)
            .map(|_| ())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    fn validate_verifying_key(&self, spki_der: &[u8]) -> CryptoResult<()> {
        RsaPublicKey::from_public_key_der(spki_der)
            .map(|_| ())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    fn generate_rsa_keypair(&self, key_id: &str) -> CryptoResult<KeyPair> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        let pkcs8 = private
            .to_pkcs8_der()
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        KeyPair::from_pkcs8_der(key_id, pkcs8.as_bytes())
    }

    fn public_key_from_private(&self, pkcs8_der: &[u8]) -> CryptoResult<Vec<u8>> {
        let private = RsaPrivateKey::from_pkcs8_der(pkcs8_der)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let public = RsaPublicKey::from(&private);
        public
            .to_public_key_der()
            .map(|der| der.to_vec())
            .map_err(|e| CryptoError::Operation(e.to_string()))
    }

    fn sign_rsa_pss_sha256(&self, key: &SigningKey, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let private = RsaPrivateKey::from_pkcs8_der(key.der())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let signing_key = PssSigningKey::<Sha256>::new(private);
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        let mut rng = rand::thread_rng();
        let signature: Signature = signing_key
            .sign_with_rng(&mut rng, message);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify_rsa_pss_sha256(
        &self,
        key: &VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> CryptoResult<()> {
        let public = RsaPublicKey::from_public_key_der(key.der())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let verifying_key = PssVerifyingKey::<Sha256>::new(public);
        let sig = Signature::try_from(signature)
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        use rsa::signature::Verifier;
        verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn wrap_key_rsa_oaep_sha256(
        &self,
        public_key: &VerifyingKey,
        content_key: &ContentEncryptionKey,
    ) -> CryptoResult<Vec<u8>> {
        let public = RsaPublicKey::from_public_key_der(public_key.der())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let padding = Oaep::new::<Sha256>();
        let mut rng = rand::thread_rng();
        public
            .encrypt(&mut rng, padding, content_key.as_bytes())
            .map_err(|e| CryptoError::Operation(e.to_string()))
    }

    fn unwrap_key_rsa_oaep_sha256(
        &self,
        private_key: &SigningKey,
        wrapped: &[u8],
    ) -> CryptoResult<ContentEncryptionKey> {
        let private = RsaPrivateKey::from_pkcs8_der(private_key.der())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let padding = Oaep::new::<Sha256>();
        let bytes = private
            .decrypt(padding, wrapped)
            .map_err(|e| CryptoError::Operation(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(CryptoError::Operation(
                "unwrapped key length is not 256 bits".into(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
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
        tag.copy_from_slice(&in_out[tag_start..]);
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
