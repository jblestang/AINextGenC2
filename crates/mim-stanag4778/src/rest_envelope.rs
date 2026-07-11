use mim_crypto::sha256_base64;
use mim_labeling::{ConfidentialityLabel, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use serde::{Deserialize, Serialize};

use crate::assertion::AssertionBinding;
use crate::binding::{BindingMethod, BindingProfile, MetadataBinding};
use crate::bdo::BindingDataObject;

/// STANAG 4778 REST envelope per ADatP-4778.2 for MIP4-IES HTTP binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestEnvelope {
    pub metadata_binding: MetadataBinding,
    pub originator_confidentiality_label: String,
    pub payload_digest: String,
    pub payload: String,
    pub assertion: Option<AssertionBinding>,
}

impl RestEnvelope {
    pub fn wrap(
        label: &ConfidentialityLabel,
        payload: &[u8],
        signing_key: &mim_crypto::SigningKey,
    ) -> LabelResult<Self> {
        label.validate()?;
        let codec = Stanag4774Codec::new();
        let label_xml = codec.serialize(label, Stanag4774Format::Xml)?;
        let assertion = AssertionBinding::create(label, payload, signing_key)?;
        Ok(Self {
            metadata_binding: MetadataBinding {
                method: BindingMethod::Assertion,
                profile: BindingProfile::RestEnvelope,
                label_location: "X-NATO-Confidentiality-Label".to_owned(),
                data_digest: Some(assertion.payload_digest.clone()),
            },
            originator_confidentiality_label: label_xml,
            payload_digest: assertion.payload_digest.clone(),
            payload: String::from_utf8(payload.to_vec())
                .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?,
            assertion: Some(assertion),
        })
    }

    pub fn from_bdo(bdo: &BindingDataObject, payload: &[u8]) -> LabelResult<Self> {
        let payload_str = String::from_utf8(payload.to_vec())
            .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;
        Ok(Self {
            metadata_binding: MetadataBinding {
                method: bdo.binding.method,
                profile: BindingProfile::RestEnvelope,
                label_location: "X-NATO-Confidentiality-Label".to_owned(),
                data_digest: Some(bdo.payload_digest.clone()),
            },
            originator_confidentiality_label: bdo.label_encoding.clone(),
            payload_digest: bdo.payload_digest.clone(),
            payload: payload_str,
            assertion: bdo.assertion.clone(),
        })
    }

    pub fn verify(&self, verifying_key: &mim_crypto::VerifyingKey) -> LabelResult<()> {
        if self.payload_digest != sha256_base64(self.payload.as_bytes()) {
            return Err(mim_labeling::LabelError::Binding(
                "REST envelope payload digest mismatch".into(),
            ));
        }
        let assertion = self.assertion.as_ref().ok_or_else(|| {
            mim_labeling::LabelError::Binding(
                "REST envelope requires NMBS assertion binding".into(),
            )
        })?;
        assertion.verify(self.payload.as_bytes(), verifying_key)
    }

    pub fn to_json(&self) -> LabelResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))
    }

    pub fn from_json(data: &str) -> LabelResult<Self> {
        serde_json::from_str(data).map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_crypto::conformance_keypair;
    use mim_labeling::{ClassificationLevel, LabelPolicy};

    use super::*;

    #[test]
    fn rest_envelope_round_trip() {
        let kp = conformance_keypair().expect("keypair");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let payload = br#"{"instances":[]}"#;
        let envelope = RestEnvelope::wrap(&label, payload, kp.signing_key()).expect("wrap");
        envelope.verify(kp.verifying_key()).expect("verify");
    }
}
