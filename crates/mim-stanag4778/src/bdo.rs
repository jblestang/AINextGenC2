use mim_labeling::{ConfidentialityLabel, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use serde::{Deserialize, Serialize};

use crate::assertion::AssertionBinding;
use crate::binding::{BindingMethod, BindingProfile, MetadataBinding};

/// Binding Data Object (BDO) per STANAG 4778.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingDataObject {
    pub binding: MetadataBinding,
    pub label: ConfidentialityLabel,
    pub label_encoding: String,
    pub assertion: Option<AssertionBinding>,
}

impl BindingDataObject {
    pub fn embedded(label: ConfidentialityLabel, _payload: &[u8]) -> LabelResult<Self> {
        label.validate()?;
        let codec = Stanag4774Codec::new();
        let encoded = codec.serialize(&label, Stanag4774Format::JsonStructured)?;
        Ok(Self {
            binding: MetadataBinding::embedded_json(),
            label,
            label_encoding: encoded,
            assertion: None,
        })
    }

    pub fn assertion_bound(
        label: ConfidentialityLabel,
        payload: &[u8],
        secret: &[u8],
    ) -> LabelResult<Self> {
        label.validate()?;
        let codec = Stanag4774Codec::new();
        let encoded = codec.serialize(&label, Stanag4774Format::Xml)?;
        let assertion = AssertionBinding::create(&label, payload, secret)?;
        Ok(Self {
            binding: MetadataBinding::assertion_ztdf(),
            label,
            label_encoding: encoded,
            assertion: Some(assertion),
        })
    }

    pub fn verify(&self, payload: &[u8], secret: Option<&[u8]>) -> LabelResult<()> {
        self.label.validate()?;
        match self.binding.method {
            BindingMethod::Assertion => {
                let assertion = self
                    .assertion
                    .as_ref()
                    .ok_or_else(|| {
                        mim_labeling::LabelError::Binding(
                            "assertion binding missing assertion block".into(),
                        )
                    })?;
                let key = secret.ok_or_else(|| {
                    mim_labeling::LabelError::Binding(
                        "assertion binding requires verification secret".into(),
                    )
                })?;
                assertion.verify(payload, key)
            }
            BindingMethod::Embedded
            | BindingMethod::Encapsulated
            | BindingMethod::Detached => {
                let _ = (payload, secret);
                Ok(())
            }
        }
    }

    pub fn profile_name(&self) -> &'static str {
        match self.binding.profile {
            BindingProfile::JsonSidecar => "JSON Sidecar (ADatP-4778.2)",
            BindingProfile::XmlEmbedded => "XML Embedded",
            BindingProfile::RestEnvelope => "REST Envelope",
            BindingProfile::SmtpHeader => "SMTP Header",
            BindingProfile::ZtdfAssertion => "ZTDF Assertion (ADatP-4778.2)",
        }
    }
}
