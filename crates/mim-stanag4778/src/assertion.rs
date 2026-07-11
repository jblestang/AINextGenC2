use mim_crypto::{
    sha256_base64, sign_nmb_binding, verify_nmb_binding, NMBS_ALGORITHM, NMBS_ALGORITHM_URI,
    SigningKey, VerifyingKey,
};
use mim_labeling::{ConfidentialityLabel, LabelError, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use serde::{Deserialize, Serialize};

/// Cryptographic signature for a STANAG 4778 NMBS assertion binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingSignature {
    pub algorithm: String,
    pub algorithm_uri: String,
    pub key_id: String,
    pub signature: String,
}

/// STANAG 4778 NMBS assertion binding with RSA-PSS-SHA256 over label + payload digest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionBinding {
    pub label: ConfidentialityLabel,
    pub payload_digest: String,
    pub signature: BindingSignature,
    /// Exact STANAG 4774 XML bytes covered by the NMBS signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_label_xml: Option<String>,
}

impl AssertionBinding {
    /// NMBS Set — create assertion binding with signing key.
    pub fn create(
        label: &ConfidentialityLabel,
        payload: &[u8],
        signing_key: &SigningKey,
    ) -> LabelResult<Self> {
        label.validate()?;
        mim_spif::SpifValidator::with_defaults().validate_label(label)?;
        let payload_digest = sha256_base64(payload);
        let codec = Stanag4774Codec::new();
        let label_xml = codec.serialize(label, Stanag4774Format::Xml)?;
        let signature = sign_binding(label, &label_xml, &payload_digest, signing_key)?;
        Ok(Self {
            label: label.clone(),
            payload_digest,
            signature,
            signed_label_xml: Some(label_xml),
        })
    }

    /// NMBS Verify — verify assertion binding with verifying key.
    pub fn verify(&self, payload: &[u8], verifying_key: &VerifyingKey) -> LabelResult<()> {
        self.label.validate()?;
        mim_spif::SpifValidator::with_defaults().validate_label(&self.label)?;
        let expected_digest = sha256_base64(payload);
        if self.payload_digest != expected_digest {
            return Err(LabelError::Binding(
                "payload digest mismatch — binding integrity failed".into(),
            ));
        }
        if self.signature.key_id != verifying_key.key_id {
            return Err(LabelError::Binding(format!(
                "NMBS key id mismatch: expected {}, got {}",
                verifying_key.key_id, self.signature.key_id
            )));
        }
        let label_bytes = if let Some(xml) = &self.signed_label_xml {
            xml.as_bytes()
        } else {
            let codec = Stanag4774Codec::new();
            let label_xml = codec.serialize(&self.label, Stanag4774Format::Xml)?;
            return verify_nmb_binding(
                verifying_key,
                label_xml.as_bytes(),
                &self.payload_digest,
                &self.signature.signature,
            )
            .map_err(|e| LabelError::Binding(e.to_string()));
        };
        verify_nmb_binding(
            verifying_key,
            label_bytes,
            &self.payload_digest,
            &self.signature.signature,
        )
        .map_err(|e| LabelError::Binding(e.to_string()))
    }
}

fn sign_binding(
    label: &ConfidentialityLabel,
    label_xml: &str,
    payload_digest: &str,
    signing_key: &SigningKey,
) -> LabelResult<BindingSignature> {
    let signature = sign_nmb_binding(signing_key, label_xml.as_bytes(), payload_digest)
        .map_err(|e| LabelError::Binding(e.to_string()))?;
    Ok(BindingSignature {
        algorithm: NMBS_ALGORITHM.to_owned(),
        algorithm_uri: NMBS_ALGORITHM_URI.to_owned(),
        key_id: signing_key.key_id.clone(),
        signature,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_crypto::conformance_keypair;
    use mim_labeling::{ClassificationLevel, LabelPolicy};

    use super::*;

    #[test]
    fn nmb_assertion_binding_round_trip() {
        let kp = conformance_keypair().expect("keypair");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let payload = br#"{"className":"Target"}"#;
        let binding =
            AssertionBinding::create(&label, payload, kp.signing_key()).expect("create");
        binding
            .verify(payload, kp.verifying_key())
            .expect("verify");
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let kp = conformance_keypair().expect("keypair");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let binding = AssertionBinding::create(&label, b"original", kp.signing_key()).expect("create");
        assert!(binding.verify(b"tampered", kp.verifying_key()).is_err());
    }
}
