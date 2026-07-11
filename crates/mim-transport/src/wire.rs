use mim_core::MimResult;
use mim_model::ModelRegistry;
use mim_runtime::SerializationFormat;

/// MIM model version advertised on the wire (MIP4-IES `MIM-Version` header).
pub const MIM_VERSION: &str = "5.1.0";

/// Official MIP4-IES JSON payload media type.
pub const MEDIA_MIM_JSON: &str = "application/mim+json";

/// Official MIP4-IES XML payload media type.
pub const MEDIA_MIM_XML: &str = "application/mim+xml";

/// Fallback JSON media type for REST envelope bodies.
pub const MEDIA_JSON: &str = "application/json";

/// MIM-Version response/request header name.
pub const HEADER_MIM_VERSION: &str = "MIM-Version";

/// Wire payload encoding for MIM instance bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WirePayloadFormat {
    Json,
    Xml,
}

impl WirePayloadFormat {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Json => MEDIA_MIM_JSON,
            Self::Xml => MEDIA_MIM_XML,
        }
    }

    pub fn serialization_format(self) -> SerializationFormat {
        match self {
            Self::Json => SerializationFormat::Json,
            Self::Xml => SerializationFormat::Xml,
        }
    }
}

pub fn detect_payload_format(payload: &str) -> WirePayloadFormat {
    if payload.trim_start().starts_with('<') {
        WirePayloadFormat::Xml
    } else {
        WirePayloadFormat::Json
    }
}

pub fn format_from_content_type(content_type: &str) -> Option<WirePayloadFormat> {
    let mime = content_type.split(';').next()?.trim().to_ascii_lowercase();
    match mime.as_str() {
        MEDIA_MIM_XML | "application/xml" | "text/xml" => Some(WirePayloadFormat::Xml),
        MEDIA_MIM_JSON | MEDIA_JSON => Some(WirePayloadFormat::Json),
        _ => None,
    }
}

/// Negotiate response format from an HTTP `Accept` header.
pub fn negotiate_format(accept: Option<&str>, default: WirePayloadFormat) -> WirePayloadFormat {
    let Some(header) = accept else {
        return default;
    };

    let mut best = None;
    for part in header.split(',') {
        let mut segment = part.trim().split(';');
        let mime = segment.next().unwrap_or("").trim().to_ascii_lowercase();
        let q = segment
            .find_map(|param| {
                let mut pieces = param.trim().split('=');
                match (pieces.next(), pieces.next()) {
                    (Some("q"), Some(value)) => value.parse::<f32>().ok(),
                    _ => None,
                }
            })
            .unwrap_or(1.0);

        let format = match mime.as_str() {
            MEDIA_MIM_XML | "application/xml" | "text/xml" => Some(WirePayloadFormat::Xml),
            MEDIA_MIM_JSON | MEDIA_JSON => Some(WirePayloadFormat::Json),
            "*/*" => Some(default),
            _ => None,
        };

        if let Some(candidate) = format {
            if best.map(|(_, best_q)| q > best_q).unwrap_or(true) {
                best = Some((candidate, q));
            }
        }
    }

    best.map(|(format, _)| format).unwrap_or(default)
}

/// Minimal registry for wire-format serialization without full model validation.
pub fn wire_registry() -> MimResult<ModelRegistry> {
    use mim_core::MimUri;
    use mim_core::SemanticId;
    use mim_model::manifest::{ModelElementKind, ModelElementSpec};
    use mim_model::TaxonomyNode;

    ModelRegistry::from_manifest(mim_model::MimManifest {
        version: MIM_VERSION.into(),
        release_date: "2020-09-28".into(),
        description: "wire".into(),
        expected_object_types: 0,
        expected_action_types: 0,
        expected_code_lists: 0,
        taxonomy: vec![TaxonomyNode {
            name: "Wire".into(),
            semantic_id: SemanticId::parse("00000000-0000-4000-8000-000000000001")?,
            parent: None,
            object_kind: None,
            action_kind: None,
            definition: "wire".into(),
            package_path: "Wire".into(),
        }],
        elements: vec![ModelElementSpec {
            name: "Wire".into(),
            kind: ModelElementKind::Class,
            semantic_id: SemanticId::parse("00000000-0000-4000-8000-000000000001")?,
            uri: MimUri::parse("https://www.mimworld.org/mim/5.1.0/Wire")?,
            package_path: "Wire".into(),
            definition: "wire".into(),
            parent_class: None,
            representation_term: None,
            representation_metadata: None,
            multiplicity_lower: None,
            multiplicity_upper: None,
            is_mandatory: false,
            is_nillable: true,
        }],
        code_lists: vec![],
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detects_xml_payload() {
        assert_eq!(
            detect_payload_format("<Unit oid=\"a\" semanticId=\"b\"/>"),
            WirePayloadFormat::Xml
        );
    }

    #[test]
    fn negotiates_accept_header() {
        assert_eq!(
            negotiate_format(
                Some("application/mim+xml;q=1.0, application/mim+json;q=0.5"),
                WirePayloadFormat::Json
            ),
            WirePayloadFormat::Xml
        );
    }
}
