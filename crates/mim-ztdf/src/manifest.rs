use base64::{engine::general_purpose::STANDARD, Engine as _};
use mim_labeling::{ConfidentialityLabel, LabelResult};
use serde::{Deserialize, Serialize};

use crate::assertion::ZtdfAssertion;

/// Supported ZTDF / OpenTDF specification version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZtdfSpecVersion;

impl ZtdfSpecVersion {
    pub const CURRENT: &'static str = "1.0.0";
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZtdfPayloadRef {
    pub payload_type: String,
    pub url: String,
    pub protocol: String,
    pub is_encrypted: bool,
    pub mime_type: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZtdfEncryptionMethod {
    pub algorithm: String,
    pub is_streamable: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZtdfEncryptionInformation {
    pub encryption_type: String,
    pub method: ZtdfEncryptionMethod,
    pub policy: String,
}

/// ZTDF manifest.json structure for labeled MIM payloads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZtdfManifest {
    pub tdf_spec_version: String,
    pub payload: ZtdfPayloadRef,
    pub encryption_information: ZtdfEncryptionInformation,
    pub assertions: Vec<ZtdfAssertion>,
}

impl ZtdfManifest {
    pub fn for_mim_payload(
        label: &ConfidentialityLabel,
        payload: &[u8],
        secret: &[u8],
        policy_b64: &str,
    ) -> LabelResult<Self> {
        let assertion = ZtdfAssertion::from_label(label, payload, secret)?;
        Ok(Self {
            tdf_spec_version: ZtdfSpecVersion::CURRENT.to_owned(),
            payload: ZtdfPayloadRef {
                payload_type: "reference".to_owned(),
                url: "0.payload".to_owned(),
                protocol: "zip".to_owned(),
                is_encrypted: false,
                mime_type: "application/json".to_owned(),
            },
            encryption_information: ZtdfEncryptionInformation {
                encryption_type: "split".to_owned(),
                method: ZtdfEncryptionMethod {
                    algorithm: "AES-256-GCM".to_owned(),
                    is_streamable: true,
                },
                policy: policy_b64.to_owned(),
            },
            assertions: vec![assertion],
        })
    }

    pub fn to_json(&self) -> LabelResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))
    }

    pub fn from_json(data: &str) -> LabelResult<Self> {
        serde_json::from_str(data).map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))
    }

    pub fn nato_label_assertion(&self) -> Option<&ZtdfAssertion> {
        self.assertions.iter().find(|a| a.id == "nato-label-1")
    }

    pub fn validate(&self) -> LabelResult<()> {
        if self.tdf_spec_version != ZtdfSpecVersion::CURRENT {
            return Err(mim_labeling::LabelError::Validation(format!(
                "unsupported tdf_spec_version: {}",
                self.tdf_spec_version
            )));
        }
        if self.assertions.is_empty() {
            return Err(mim_labeling::LabelError::Validation(
                "ZTDF manifest requires at least one assertion".into(),
            ));
        }
        let nato = self
            .nato_label_assertion()
            .ok_or_else(|| {
                mim_labeling::LabelError::Validation(
                    "ZTDF manifest requires nato-label-1 assertion".into(),
                )
            })?;
        if nato.statement.schema != mim_stanag4774::NAMESPACE {
            return Err(mim_labeling::LabelError::Validation(
                "assertion schema must be STANAG 4774 namespace".into(),
            ));
        }
        Ok(())
    }
}

pub fn default_policy_b64() -> String {
    let policy = serde_json::json!({
        "uuid": "61333466-4f0a-4a12-95fb-b6d8bd0b8b26",
        "body": {
            "attributes": ["classification", "releasableTo"],
            "dissem": ["coalition"]
        }
    });
    STANDARD.encode(policy.to_string())
}
