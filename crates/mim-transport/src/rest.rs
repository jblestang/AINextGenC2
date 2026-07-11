use serde::{Deserialize, Serialize};

use crate::error::{TransportError, TransportResult};
use crate::filter::parse_filter;
use crate::message::{
    DeleteObjectRequest, GetByFilterRequest, GetByOidRequest, IesOperation, PutObjectRequest,
};

/// MIP4-IES REST binding paths (v4.4+ preferred over legacy SOAP/WSMP).
pub mod paths {
    pub const API_VERSION: &str = "v1";
    pub const BASE: &str = "/mip4-ies/v1";
    pub const OBJECTS: &str = "/mip4-ies/v1/objects";
    pub const SYNC: &str = "/mip4-ies/v1/sync";
}

/// HTTP methods mapped to MIP4-IES operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Put,
    Delete,
}

/// REST route descriptor for an IES operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestRoute {
    pub method: HttpMethod,
    pub path: String,
    pub operation: IesOperation,
}

/// Parse a REST request into an IES operation route.
pub fn parse_route(method: HttpMethod, path: &str) -> TransportResult<RestRoute> {
    let normalized = normalize_path(path);

    match method {
        HttpMethod::Put if normalized == paths::OBJECTS => Ok(RestRoute {
            method,
            path: normalized,
            operation: IesOperation::PutObject,
        }),
        HttpMethod::Get if normalized == paths::OBJECTS => Ok(RestRoute {
            method,
            path: normalized,
            operation: IesOperation::GetByFilter,
        }),
        HttpMethod::Get if normalized.starts_with(&format!("{}/", paths::OBJECTS)) => {
            Ok(RestRoute {
                method,
                path: normalized,
                operation: IesOperation::GetByOid,
            })
        }
        HttpMethod::Delete if normalized.starts_with(&format!("{}/", paths::OBJECTS)) => {
            Ok(RestRoute {
                method,
                path: normalized,
                operation: IesOperation::DeleteObject,
            })
        }
        HttpMethod::Get if normalized == paths::SYNC => Ok(RestRoute {
            method,
            path: normalized,
            operation: IesOperation::Sync,
        }),
        _ => Err(TransportError::Unsupported(format!(
            "no MIP4-IES route for {method:?} {path}"
        ))),
    }
}

/// Extract OID suffix from `/mip4-ies/v1/objects/{oid}`.
pub fn oid_from_path(path: &str) -> TransportResult<String> {
    let prefix = format!("{}/", paths::OBJECTS);
    let normalized = normalize_path(path);
    normalized
        .strip_prefix(&prefix)
        .map(str::to_owned)
        .filter(|oid| !oid.is_empty())
        .ok_or_else(|| {
            TransportError::InvalidRequest(format!("expected path {prefix}{{oid}}, got {path}"))
        })
}

/// Percent-encode an OID for use in REST path segments (`urn:uuid:…` → safe path token).
pub fn encode_oid_for_path(oid: &str) -> String {
    let mut encoded = String::with_capacity(oid.len() + 8);
    for byte in oid.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
                encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
            }
        }
    }
    encoded
}

/// Build REST path for GetByOID / DeleteObject with URL-encoded OID.
pub fn object_path(oid: &str) -> String {
    format!("{}/{}", paths::OBJECTS, encode_oid_for_path(oid))
}

/// Deserialize a PutObject body from JSON.
pub fn parse_put_body(body: &str) -> TransportResult<PutObjectRequest> {
    serde_json::from_str(body).map_err(|e| TransportError::Serialization(e.to_string()))
}

/// Deserialize a GetByFilter query from JSON body (REST POST-style filter) or query map.
pub fn parse_filter_body(body: &str) -> TransportResult<GetByFilterRequest> {
    serde_json::from_str(body).map_err(|e| TransportError::Serialization(e.to_string()))
}

/// Build a GetByFilter request from query parameters.
pub fn filter_from_query(
    filter: Option<&str>,
    class_name: Option<&str>,
    property_name: Option<&str>,
    property_value: Option<&str>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> TransportResult<GetByFilterRequest> {
    if let Some(expression) = filter.filter(|value| !value.is_empty()) {
        parse_filter(expression)?;
        return Ok(GetByFilterRequest {
            filter: Some(expression.to_owned()),
            class_name: String::new(),
            property_name: None,
            property_value: None,
            limit,
            offset,
        });
    }

    let class_name = class_name
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            TransportError::InvalidRequest("filter or className query parameter is required".into())
        })?
        .to_owned();

    Ok(GetByFilterRequest {
        filter: None,
        class_name,
        property_name: property_name.map(str::to_owned),
        property_value: property_value.map(str::to_owned),
        limit,
        offset,
    })
}

/// Deserialize a GetByOID request from path + optional body.
pub fn parse_get_by_oid(path: &str) -> TransportResult<GetByOidRequest> {
    let oid = mim_runtime::ObjectIdentifier::new(oid_from_path(path)?)?;
    Ok(GetByOidRequest { oid })
}

/// Deserialize a DeleteObject request from path.
pub fn parse_delete(path: &str) -> TransportResult<DeleteObjectRequest> {
    let oid = mim_runtime::ObjectIdentifier::new(oid_from_path(path)?)?;
    Ok(DeleteObjectRequest { oid })
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let without_query = trimmed.split('?').next().unwrap_or(trimmed);
    without_query.trim_end_matches('/').to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_object_routes() {
        let route = parse_route(HttpMethod::Get, "/mip4-ies/v1/objects/urn:uuid:abc").expect("route");
        assert_eq!(route.operation, IesOperation::GetByOid);

        let route = parse_route(HttpMethod::Delete, "/mip4-ies/v1/objects/urn:uuid:abc")
            .expect("route");
        assert_eq!(route.operation, IesOperation::DeleteObject);

        let route = parse_route(HttpMethod::Put, "/mip4-ies/v1/objects").expect("route");
        assert_eq!(route.operation, IesOperation::PutObject);
    }

    #[test]
    fn builds_object_path() {
        assert_eq!(
            object_path("urn:uuid:abc"),
            "/mip4-ies/v1/objects/urn%3Auuid%3Aabc"
        );
    }
}
