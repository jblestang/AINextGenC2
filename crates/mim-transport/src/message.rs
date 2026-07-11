use mim_runtime::{MimInstance, ObjectIdentifier};
use serde::{Deserialize, Serialize};

/// MIP4-IES service operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IesOperation {
    PutObject,
    GetByOid,
    GetByFilter,
    DeleteObject,
}

/// PutObject — publish or update a MIM instance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutObjectRequest {
    pub instance: MimInstance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutObjectResponse {
    pub oid: ObjectIdentifier,
    pub created: bool,
}

/// GetByOID — retrieve a single instance by object identifier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetByOidRequest {
    pub oid: ObjectIdentifier,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetByOidResponse {
    pub instance: MimInstance,
}

/// GetByFilter — retrieve instances matching class and optional property criteria.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetByFilterRequest {
    /// MIP4-IES XPath-like filter (`//ClassName[@prop='value']`). Preferred for FMN REST binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(default)]
    pub class_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property_value: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetByFilterResponse {
    pub instances: Vec<MimInstance>,
    pub count: usize,
}

/// DeleteObject — mark an instance inactive (MIP4-IES soft delete).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteObjectRequest {
    pub oid: ObjectIdentifier,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteObjectResponse {
    pub oid: ObjectIdentifier,
    pub deleted: bool,
}

/// Wire envelope for MIP4-IES exchange messages.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeEnvelope {
    pub operation: IesOperation,
    pub model_version: String,
    pub content_type: String,
    pub payload: String,
}

impl ExchangeEnvelope {
    pub fn new(
        operation: IesOperation,
        model_version: impl Into<String>,
        payload: impl Into<String>,
    ) -> Self {
        Self {
            operation,
            model_version: model_version.into(),
            content_type: "application/mim+json".to_owned(),
            payload: payload.into(),
        }
    }
}
