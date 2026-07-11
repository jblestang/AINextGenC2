use serde::{Deserialize, Serialize};

/// STANAG 4778 binding method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BindingMethod {
    Embedded,
    Encapsulated,
    Detached,
    Assertion,
}

/// ADatP-4778.2 binding profile for a specific data format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BindingProfile {
    JsonSidecar,
    XmlEmbedded,
    RestEnvelope,
    SmtpHeader,
    ZtdfAssertion,
}

/// Metadata binding associating a label with a data object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataBinding {
    pub method: BindingMethod,
    pub profile: BindingProfile,
    pub label_location: String,
    pub data_digest: Option<String>,
}

impl MetadataBinding {
    pub fn embedded_json() -> Self {
        Self {
            method: BindingMethod::Embedded,
            profile: BindingProfile::JsonSidecar,
            label_location: "metadata.security".to_owned(),
            data_digest: None,
        }
    }

    pub fn assertion_ztdf() -> Self {
        Self {
            method: BindingMethod::Assertion,
            profile: BindingProfile::ZtdfAssertion,
            label_location: "assertions[nato-label]".to_owned(),
            data_digest: None,
        }
    }

    pub fn encapsulated_xml() -> Self {
        Self {
            method: BindingMethod::Encapsulated,
            profile: BindingProfile::XmlEmbedded,
            label_location: "originatorConfidentialityLabel".to_owned(),
            data_digest: None,
        }
    }
}
