use mim_crypto::SigningKey;
use mim_labeling::{ConfidentialityLabel, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format, NAMESPACE};
use mim_stanag4778::AssertionBinding;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// ZTDF assertion statement carrying a STANAG 4774 label with NMBS binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZtdfAssertion {
    pub id: String,
    pub assertion_type: String,
    pub scope: String,
    pub applies_to_state: String,
    pub statement: ZtdfStatement,
    pub binding: ZtdfAssertionBinding,
    /// Exact STANAG 4774 XML bytes included in the NMBS signature.
    pub signed_label_xml: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZtdfStatement {
    pub format: String,
    pub schema: String,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZtdfAssertionBinding {
    pub method: String,
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

impl ZtdfAssertion {
    pub fn from_label(
        label: &ConfidentialityLabel,
        payload: &[u8],
        signing_key: &SigningKey,
    ) -> LabelResult<Self> {
        label.validate()?;
        let codec = Stanag4774Codec::new();
        let label_xml = codec.serialize(label, Stanag4774Format::Xml)?;
        let json_value: Value = serde_json::from_str(
            &codec.serialize(label, Stanag4774Format::JsonStructured)?,
        )
        .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;

        let assertion = AssertionBinding::create(label, payload, signing_key)?;

        Ok(Self {
            id: "nato-label-1".to_owned(),
            assertion_type: "handling".to_owned(),
            scope: "payload".to_owned(),
            applies_to_state: "encrypted".to_owned(),
            statement: ZtdfStatement {
                format: "json-structured".to_owned(),
                schema: NAMESPACE.to_owned(),
                value: json_value,
            },
            binding: ZtdfAssertionBinding {
                method: "nmb".to_owned(),
                algorithm: assertion.signature.algorithm.clone(),
                key_id: assertion.signature.key_id.clone(),
                signature: assertion.signature.signature.clone(),
            },
            signed_label_xml: label_xml,
        })
    }
}
