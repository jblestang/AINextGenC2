use mim_labeling::{ConfidentialityLabel, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format, NAMESPACE};
use mim_stanag4778::AssertionBinding;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// ZTDF assertion statement carrying a STANAG 4774 label.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZtdfAssertion {
    pub id: String,
    pub assertion_type: String,
    pub scope: String,
    pub applies_to_state: String,
    pub statement: ZtdfStatement,
    pub binding: ZtdfAssertionBinding,
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
    pub signature: String,
}

impl ZtdfAssertion {
    pub fn from_label(
        label: &ConfidentialityLabel,
        payload: &[u8],
        secret: &[u8],
    ) -> LabelResult<Self> {
        label.validate()?;
        let codec = Stanag4774Codec::new();
        let json_value: Value = serde_json::from_str(
            &codec.serialize(label, Stanag4774Format::JsonStructured)?,
        )
        .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;

        let assertion = AssertionBinding::create(label, payload, secret)?;

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
                method: "hmac".to_owned(),
                signature: assertion.signature.signature,
            },
        })
    }
}
