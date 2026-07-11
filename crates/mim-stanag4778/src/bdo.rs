use mim_crypto::sha256_base64;
use mim_labeling::{ConfidentialityLabel, LabelError, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use serde::{Deserialize, Serialize};

use crate::assertion::AssertionBinding;
use crate::binding::{BindingMethod, BindingProfile, MetadataBinding};
use crate::detached::{DetachedLabelResolver, FileDetachedLabelResolver, verify_detached_label};

/// Binding Data Object (BDO) per STANAG 4778 with integrity verification for all profiles.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingDataObject {
    pub binding: MetadataBinding,
    pub label: ConfidentialityLabel,
    pub label_encoding: String,
    pub payload_digest: String,
    pub assertion: Option<AssertionBinding>,
}

impl BindingDataObject {
    pub fn embedded(label: ConfidentialityLabel, payload: &[u8]) -> LabelResult<Self> {
        Self::embedded_with_nmb(label, payload, None)
    }

    pub fn embedded_with_nmb(
        label: ConfidentialityLabel,
        payload: &[u8],
        signing_key: Option<&mim_crypto::SigningKey>,
    ) -> LabelResult<Self> {
        label.validate()?;
        mim_spif::SpifValidator::with_defaults().validate_label(&label)?;
        let codec = Stanag4774Codec::new();
        let encoded = codec.serialize(&label, Stanag4774Format::JsonStructured)?;
        let assertion = signing_key
            .map(|key| AssertionBinding::create(&label, payload, key))
            .transpose()?;
        Ok(Self {
            binding: MetadataBinding::embedded_json(),
            label,
            label_encoding: encoded,
            payload_digest: sha256_base64(payload),
            assertion,
        })
    }

    pub fn xml_embedded(label: ConfidentialityLabel, payload: &[u8]) -> LabelResult<Self> {
        Self::xml_embedded_with_nmb(label, payload, None)
    }

    pub fn xml_embedded_with_nmb(
        label: ConfidentialityLabel,
        payload: &[u8],
        signing_key: Option<&mim_crypto::SigningKey>,
    ) -> LabelResult<Self> {
        label.validate()?;
        mim_spif::SpifValidator::with_defaults().validate_label(&label)?;
        let codec = Stanag4774Codec::new();
        let encoded = codec.serialize(&label, Stanag4774Format::Xml)?;
        let assertion = signing_key
            .map(|key| AssertionBinding::create(&label, payload, key))
            .transpose()?;
        Ok(Self {
            binding: MetadataBinding::encapsulated_xml(),
            label,
            label_encoding: encoded,
            payload_digest: sha256_base64(payload),
            assertion,
        })
    }

    pub fn encapsulated(label: ConfidentialityLabel, payload: &[u8]) -> LabelResult<Self> {
        Self::encapsulated_with_nmb(label, payload, None)
    }

    pub fn encapsulated_with_nmb(
        label: ConfidentialityLabel,
        payload: &[u8],
        signing_key: Option<&mim_crypto::SigningKey>,
    ) -> LabelResult<Self> {
        label.validate()?;
        mim_spif::SpifValidator::with_defaults().validate_label(&label)?;
        let codec = Stanag4774Codec::new();
        let encoded = codec.serialize(&label, Stanag4774Format::Xml)?;
        let assertion = signing_key
            .map(|key| AssertionBinding::create(&label, payload, key))
            .transpose()?;
        Ok(Self {
            binding: MetadataBinding {
                method: BindingMethod::Encapsulated,
                profile: BindingProfile::XmlEmbedded,
                label_location: "ConfidentialityLabel".to_owned(),
                data_digest: Some(sha256_base64(payload)),
            },
            label,
            label_encoding: encoded,
            payload_digest: sha256_base64(payload),
            assertion,
        })
    }

    pub fn detached(label: ConfidentialityLabel, payload: &[u8], label_uri: &str) -> LabelResult<Self> {
        Self::detached_with_nmb(label, payload, label_uri, None)
    }

    pub fn detached_with_nmb(
        label: ConfidentialityLabel,
        payload: &[u8],
        label_uri: &str,
        signing_key: Option<&mim_crypto::SigningKey>,
    ) -> LabelResult<Self> {
        label.validate()?;
        mim_spif::SpifValidator::with_defaults().validate_label(&label)?;
        let codec = Stanag4774Codec::new();
        let encoded = codec.serialize(&label, Stanag4774Format::Xml)?;
        let assertion = signing_key
            .map(|key| AssertionBinding::create(&label, payload, key))
            .transpose()?;
        Ok(Self {
            binding: MetadataBinding {
                method: BindingMethod::Detached,
                profile: BindingProfile::JsonSidecar,
                label_location: label_uri.to_owned(),
                data_digest: Some(sha256_base64(payload)),
            },
            label,
            label_encoding: encoded,
            payload_digest: sha256_base64(payload),
            assertion,
        })
    }

    pub fn assertion_bound(
        label: ConfidentialityLabel,
        payload: &[u8],
        signing_key: &mim_crypto::SigningKey,
    ) -> LabelResult<Self> {
        label.validate()?;
        let codec = Stanag4774Codec::new();
        let encoded = codec.serialize(&label, Stanag4774Format::Xml)?;
        let assertion = AssertionBinding::create(&label, payload, signing_key)?;
        Ok(Self {
            binding: MetadataBinding::assertion_ztdf(),
            label,
            label_encoding: encoded,
            payload_digest: assertion.payload_digest.clone(),
            assertion: Some(assertion),
        })
    }

    pub fn verify(&self, payload: &[u8], verifying_key: Option<&mim_crypto::VerifyingKey>) -> LabelResult<()> {
        self.verify_with_resolver(payload, verifying_key, &FileDetachedLabelResolver)
    }

    pub fn verify_with_resolver(
        &self,
        payload: &[u8],
        verifying_key: Option<&mim_crypto::VerifyingKey>,
        resolver: &dyn DetachedLabelResolver,
    ) -> LabelResult<()> {
        self.label.validate()?;
        let digest = sha256_base64(payload);
        if self.payload_digest != digest {
            return Err(LabelError::Binding(
                "payload digest mismatch for binding profile".into(),
            ));
        }
        if let Some(expected) = &self.binding.data_digest {
            if expected != &digest {
                return Err(LabelError::Binding(
                    "metadata binding data digest mismatch".into(),
                ));
            }
        }

        if let Some(assertion) = &self.assertion {
            let key = verifying_key.ok_or_else(|| {
                LabelError::Binding("NMBS assertion present but no verifying key supplied".into())
            })?;
            assertion.verify(payload, key)?;
        }

        match self.binding.method {
            BindingMethod::Assertion => {
                let assertion = self.assertion.as_ref().ok_or_else(|| {
                    LabelError::Binding("assertion binding missing assertion block".into())
                })?;
                let key = verifying_key.ok_or_else(|| {
                    LabelError::Binding(
                        "assertion binding requires NMBS verifying key".into(),
                    )
                })?;
                assertion.verify(payload, key)
            }
            BindingMethod::Detached => {
                verify_detached_label(&self.label, &self.binding.label_location, resolver)?;
                mim_spif::SpifValidator::with_defaults().validate_label(&self.label)?;
                Ok(())
            }
            BindingMethod::Embedded | BindingMethod::Encapsulated => {
                mim_spif::SpifValidator::with_defaults().validate_label(&self.label)?;
                Ok(())
            }
        }
    }

    pub fn profile_name(&self) -> &'static str {
        match self.binding.profile {
            BindingProfile::JsonSidecar => "JSON Sidecar (ADatP-4778.2)",
            BindingProfile::XmlEmbedded => "XML Embedded",
            BindingProfile::RestEnvelope => "REST Envelope (ADatP-4778.2)",
            BindingProfile::SmtpHeader => "SMTP Header (ADatP-4778.2)",
            BindingProfile::ZtdfAssertion => "ZTDF Assertion (ADatP-4778.2)",
        }
    }

    pub fn requires_assertion_binding(&self) -> bool {
        self.binding.method == BindingMethod::Assertion
    }

    pub fn has_nmb_signature(&self) -> bool {
        self.assertion.is_some()
    }
}
