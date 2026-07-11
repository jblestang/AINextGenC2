use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use mim_labeling::{ConfidentialityLabel, LabelError, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Cryptographic signature for a STANAG 4778 assertion binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingSignature {
    pub algorithm: String,
    pub signature: String,
}

/// STANAG 4778 assertion binding with HMAC-SHA256 over label + payload hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionBinding {
    pub label: ConfidentialityLabel,
    pub payload_digest: String,
    pub signature: BindingSignature,
}

impl AssertionBinding {
    pub fn create(
        label: &ConfidentialityLabel,
        payload: &[u8],
        secret: &[u8],
    ) -> LabelResult<Self> {
        label.validate()?;
        let payload_digest = sha256_base64(payload);
        let signature = sign_binding(label, &payload_digest, secret)?;
        Ok(Self {
            label: label.clone(),
            payload_digest,
            signature,
        })
    }

    pub fn verify(&self, payload: &[u8], secret: &[u8]) -> LabelResult<()> {
        self.label.validate()?;
        let expected_digest = sha256_base64(payload);
        if self.payload_digest != expected_digest {
            return Err(LabelError::Binding(
                "payload digest mismatch — binding integrity failed".into(),
            ));
        }
        let expected_sig = sign_binding(&self.label, &self.payload_digest, secret)?;
        if self.signature.signature != expected_sig.signature {
            return Err(LabelError::Binding(
                "assertion signature verification failed".into(),
            ));
        }
        Ok(())
    }
}

fn sign_binding(
    label: &ConfidentialityLabel,
    payload_digest: &str,
    secret: &[u8],
) -> LabelResult<BindingSignature> {
    let codec = Stanag4774Codec::new();
    let label_xml = codec.serialize(label, Stanag4774Format::Xml)?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| LabelError::Binding(e.to_string()))?;
    mac.update(label_xml.as_bytes());
    mac.update(b"|");
    mac.update(payload_digest.as_bytes());
    let result = mac.finalize().into_bytes();
    Ok(BindingSignature {
        algorithm: "HMAC-SHA256".to_owned(),
        signature: STANDARD.encode(result),
    })
}

fn sha256_base64(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    STANDARD.encode(digest)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{ClassificationLevel, LabelPolicy};

    use super::*;

    #[test]
    fn assertion_binding_round_trip() {
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let payload = br#"{"className":"Target"}"#;
        let secret = b"binding-secret-key-32bytes-long!!";
        let binding = AssertionBinding::create(&label, payload, secret).expect("create");
        binding.verify(payload, secret).expect("verify");
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let binding = AssertionBinding::create(&label, b"original", b"secret").expect("create");
        assert!(binding.verify(b"tampered", b"secret").is_err());
    }
}
