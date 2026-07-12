use std::io::{Cursor, Read, Write};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use mim_crypto::{
    selected_provider, sha256_base64, AesGcmCiphertext, ContentEncryptionKey, SigningKey,
    VerifyingKey,
};
use mim_labeling::{ConfidentialityLabel, LabelResult};
use mim_stanag4778::{AssertionBinding, BindingDataObject, BindingSignature, MetadataBinding};
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::manifest::{default_policy_b64, ZtdfManifest};

const PAYLOAD_ENTRY: &str = "0.payload";
const MANIFEST_ENTRY: &str = "manifest.json";

/// A complete ZTDF package: ZIP archive with encrypted payload + manifest + NMBS binding.
#[derive(Clone, Debug, PartialEq)]
pub struct ZtdfPackage {
    pub manifest: ZtdfManifest,
    pub encrypted_payload: Vec<u8>,
    pub content_key: ContentEncryptionKey,
    pub binding: BindingDataObject,
}

impl ZtdfPackage {
    pub fn create(
        label: &ConfidentialityLabel,
        plaintext: Vec<u8>,
        signing_key: &SigningKey,
        verifying_key: &VerifyingKey,
        kas_public_key: &VerifyingKey,
    ) -> LabelResult<Self> {
        label.validate()?;
        let policy = default_policy_b64();
        let cek = ContentEncryptionKey::generate()
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))?;
        let provider = selected_provider();
        let encrypted = provider
            .encrypt_aes256_gcm(&cek, &plaintext, b"ztdf/0.payload")
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))?;
        let encrypted_bytes = encrypted.to_bytes();

        let manifest = ZtdfManifest::for_mim_payload(
            label,
            &plaintext,
            &encrypted,
            &cek,
            signing_key,
            kas_public_key,
            &policy,
        )?;
        manifest.validate()?;

        let binding = BindingDataObject::assertion_bound(label.clone(), &plaintext, signing_key)?;
        binding.verify(&plaintext, Some(verifying_key))?;

        Ok(Self {
            manifest,
            encrypted_payload: encrypted_bytes,
            content_key: cek,
            binding,
        })
    }

    pub fn decrypt(&self, kas_private_key: &SigningKey) -> LabelResult<Vec<u8>> {
        let wrapped = STANDARD
            .decode(&self.manifest.encryption_information.key_wrap.wrapped_key)
            .map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))?;
        let provider = selected_provider();
        let cek = provider
            .unwrap_key_rsa_oaep_sha256(kas_private_key, &wrapped)
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))?;
        let ciphertext = AesGcmCiphertext::from_bytes(&self.encrypted_payload)
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))?;
        provider
            .decrypt_aes256_gcm(&cek, &ciphertext, b"ztdf/0.payload")
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))
    }

    pub fn verify(&self, verifying_key: &VerifyingKey, kas_private_key: &SigningKey) -> LabelResult<()> {
        self.manifest.validate()?;
        let plaintext = self.decrypt(kas_private_key)?;
        self.binding.verify(&plaintext, Some(verifying_key))?;
        if let Some(assertion) = &self.binding.assertion {
            assertion.verify(&plaintext, verifying_key)?;
        }
        Ok(())
    }

    pub fn to_zip_bytes(&self) -> LabelResult<Vec<u8>> {
        let manifest_json = self.manifest.to_json()?;
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buffer);
            let options = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file(MANIFEST_ENTRY, options)
                .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;
            zip.write_all(manifest_json.as_bytes())
                .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;
            zip.start_file(PAYLOAD_ENTRY, options)
                .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;
            zip.write_all(&self.encrypted_payload)
                .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;
            zip.finish()
                .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;
        }
        Ok(buffer.into_inner())
    }

    pub fn from_zip_bytes(
        data: &[u8],
        verifying_key: &VerifyingKey,
        kas_private_key: &SigningKey,
    ) -> LabelResult<Self> {
        let cursor = Cursor::new(data);
        let mut archive =
            ZipArchive::new(cursor).map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))?;
        let mut manifest_data = String::new();
        archive
            .by_name(MANIFEST_ENTRY)
            .map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))?
            .read_to_string(&mut manifest_data)
            .map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))?;
        let manifest = ZtdfManifest::from_json(&manifest_data)?;
        let mut encrypted_payload = Vec::new();
        archive
            .by_name(PAYLOAD_ENTRY)
            .map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))?
            .read_to_end(&mut encrypted_payload)
            .map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))?;

        let wrapped = STANDARD
            .decode(&manifest.encryption_information.key_wrap.wrapped_key)
            .map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))?;
        let provider = selected_provider();
        let content_key = provider
            .unwrap_key_rsa_oaep_sha256(kas_private_key, &wrapped)
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))?;

        let ciphertext = AesGcmCiphertext::from_bytes(&encrypted_payload)
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))?;
        let plaintext = provider
            .decrypt_aes256_gcm(&content_key, &ciphertext, b"ztdf/0.payload")
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))?;

        let label = manifest
            .nato_label_assertion()
            .and_then(|a| {
                serde_json::to_string(&a.statement.value)
                    .ok()
                    .and_then(|json| {
                        mim_stanag4774::Stanag4774Codec::new()
                            .deserialize(&json, mim_stanag4774::Stanag4774Format::JsonStructured)
                            .ok()
                    })
            })
            .ok_or_else(|| mim_labeling::LabelError::Validation("missing label assertion".into()))?;

        let ztdf_assertion = manifest
            .nato_label_assertion()
            .ok_or_else(|| mim_labeling::LabelError::Validation("missing nato-label-1".into()))?;

        let payload_digest = sha256_base64(&plaintext);
        if ztdf_assertion.binding.key_id != verifying_key.key_id {
            return Err(mim_labeling::LabelError::Binding(format!(
                "NMBS key id mismatch: expected {}, got {}",
                verifying_key.key_id, ztdf_assertion.binding.key_id
            )));
        }
        let assertion = AssertionBinding {
            label: label.clone(),
            payload_digest,
            signature: BindingSignature {
                algorithm: ztdf_assertion.binding.algorithm.clone(),
                algorithm_uri: mim_crypto::NMBS_ALGORITHM_URI.to_owned(),
                key_id: ztdf_assertion.binding.key_id.clone(),
                signature: ztdf_assertion.binding.signature.clone(),
            },
            signed_label_xml: Some(ztdf_assertion.signed_label_xml.clone()),
        };
        assertion.verify(&plaintext, verifying_key)?;

        let codec = mim_stanag4774::Stanag4774Codec::new();
        let label_encoding = codec.serialize(&label, mim_stanag4774::Stanag4774Format::Xml)?;
        let binding = BindingDataObject {
            binding: MetadataBinding::assertion_ztdf(),
            label: label.clone(),
            label_encoding,
            payload_digest: assertion.payload_digest.clone(),
            assertion: Some(assertion),
        };

        let package = Self {
            manifest,
            encrypted_payload,
            content_key,
            binding,
        };
        package.verify(verifying_key, kas_private_key)?;
        Ok(package)
    }

    pub fn manifest_json(&self) -> LabelResult<String> {
        self.manifest.to_json()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_crypto::conformance_key_ring;
    use mim_labeling::{CategoryMarking, ClassificationLevel, LabelPolicy};

    use super::*;

    #[test]
    fn package_create_verify_and_zip_roundtrip() {
        let ring = conformance_key_ring().expect("key ring");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let payload = br#"{"modelVersion":"5.1.0"}"#.to_vec();
        let package = ZtdfPackage::create(
            &label,
            payload.clone(),
            ring.nmb_signing(),
            ring.nmb_verifying(),
            ring.kas_verifying(),
        )
        .expect("create");
        package
            .verify(ring.nmb_verifying(), ring.kas_signing())
            .expect("verify");
        let decrypted = package.decrypt(ring.kas_signing()).expect("decrypt");
        assert_eq!(decrypted, payload);
        let zip = package.to_zip_bytes().expect("zip");
        let restored =
            ZtdfPackage::from_zip_bytes(&zip, ring.nmb_verifying(), ring.kas_signing())
                .expect("from zip");
        restored
            .verify(ring.nmb_verifying(), ring.kas_signing())
            .expect("restored verify");
    }

    #[test]
    fn kas_wrapped_cek_requires_kas_private_key() {
        let ring = conformance_key_ring().expect("key ring");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let payload = b"classified-payload".to_vec();
        let package = ZtdfPackage::create(
            &label,
            payload,
            ring.nmb_signing(),
            ring.nmb_verifying(),
            ring.kas_verifying(),
        )
        .expect("create");
        assert!(package.decrypt(ring.nmb_signing()).is_err());
        assert!(package.decrypt(ring.kas_signing()).is_ok());
    }
}
