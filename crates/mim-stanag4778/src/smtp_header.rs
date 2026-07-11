use mim_crypto::sha256_base64;
use mim_labeling::{ConfidentialityLabel, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use serde::{Deserialize, Serialize};

use crate::assertion::AssertionBinding;

/// STANAG 4778 SMTP header binding profile (ADatP-4778.2).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmtpHeaderBinding {
    pub header_name: String,
    pub label_encoding: String,
    pub payload_digest: String,
    pub assertion: AssertionBinding,
}

impl SmtpHeaderBinding {
    pub const HEADER: &'static str = "X-NATO-Confidentiality-Label";

    pub fn create(
        label: &ConfidentialityLabel,
        payload: &[u8],
        signing_key: &mim_crypto::SigningKey,
    ) -> LabelResult<Self> {
        let codec = Stanag4774Codec::new();
        let encoded = codec.serialize(label, Stanag4774Format::Xml)?;
        let assertion = AssertionBinding::create(label, payload, signing_key)?;
        Ok(Self {
            header_name: Self::HEADER.to_owned(),
            label_encoding: encoded,
            payload_digest: sha256_base64(payload),
            assertion,
        })
    }

    pub fn verify(&self, payload: &[u8], verifying_key: &mim_crypto::VerifyingKey) -> LabelResult<()> {
        if self.payload_digest != sha256_base64(payload) {
            return Err(mim_labeling::LabelError::Binding(
                "SMTP header binding payload digest mismatch".into(),
            ));
        }
        self.assertion.verify(payload, verifying_key)
    }
}
