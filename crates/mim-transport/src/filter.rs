use mim_runtime::MimInstance;

use crate::error::{TransportError, TransportResult};

/// Parsed MIP4-IES GetByFilter XPath subset (`//ClassName[@prop='value']`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterExpression {
    pub class_name: String,
    pub predicates: Vec<FilterPredicate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterPredicate {
    pub property_name: String,
    pub value: String,
}

/// Parse a MIP4-IES filter expression (XPath subset over MIM XML representation).
///
/// Supported forms:
/// - `//Target`
/// - `//Target[nameText='HOSTILE-1']`
/// - `//Target[@nameText="HOSTILE-1"]`
pub fn parse_filter(expression: &str) -> TransportResult<FilterExpression> {
    let trimmed = expression.trim();
    if !trimmed.starts_with("//") {
        return Err(TransportError::InvalidRequest(format!(
            "filter must start with //, got '{expression}'"
        )));
    }

    let body = &trimmed[2..];
    let bracket = body.find('[');
    let (class_name, predicate_text) = match bracket {
        Some(idx) => (&body[..idx], Some(&body[idx..])),
        None => (body, None),
    };

    if class_name.is_empty() {
        return Err(TransportError::InvalidRequest(
            "filter missing class name after //".into(),
        ));
    }

    let mut predicates = Vec::new();
    if let Some(text) = predicate_text {
        predicates.push(parse_predicate(text)?);
    }

    Ok(FilterExpression {
        class_name: class_name.to_owned(),
        predicates,
    })
}

fn parse_predicate(text: &str) -> TransportResult<FilterPredicate> {
    let inner = text
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| {
            TransportError::InvalidRequest(format!("malformed filter predicate: {text}"))
        })?;

    let inner = inner.trim().trim_start_matches('@').trim();
    let eq = inner
        .find('=')
        .ok_or_else(|| TransportError::InvalidRequest(format!("predicate missing =: {text}")))?;
    let (name, raw_value) = inner.split_at(eq);
    let name = name.trim();
    if name.is_empty() {
        return Err(TransportError::InvalidRequest(format!(
            "predicate missing property name: {text}"
        )));
    }

    let value = parse_quoted_value(raw_value.trim_start_matches('=').trim())?;
    Ok(FilterPredicate {
        property_name: name.to_owned(),
        value,
    })
}

fn parse_quoted_value(raw: &str) -> TransportResult<String> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return Err(TransportError::InvalidRequest(
            "predicate value must be quoted".into(),
        ));
    }
    let quote = bytes[0];
    if quote != b'\'' && quote != b'"' {
        return Err(TransportError::InvalidRequest(format!(
            "predicate value must be quoted: {raw}"
        )));
    }
    if bytes.len() < 2 || bytes[bytes.len() - 1] != quote {
        return Err(TransportError::InvalidRequest(format!(
            "unterminated predicate value: {raw}"
        )));
    }
    Ok(String::from_utf8_lossy(&bytes[1..bytes.len() - 1]).into_owned())
}

pub fn instance_matches(instance: &MimInstance, filter: &FilterExpression) -> bool {
    if instance.class_name != filter.class_name {
        return false;
    }
    filter.predicates.iter().all(|predicate| {
        instance
            .property(&predicate.property_name)
            .and_then(|property| property.value.as_option())
            .and_then(|value| value.as_str())
            .is_some_and(|actual| actual == predicate.value)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::SemanticId;
    use mim_runtime::{MimInstance, PropertyValue};

    use super::*;

    #[test]
    fn parses_class_only_filter() {
        let filter = parse_filter("//Target").expect("parse");
        assert_eq!(filter.class_name, "Target");
        assert!(filter.predicates.is_empty());
    }

    #[test]
    fn parses_predicate_with_at_sign() {
        let filter = parse_filter("//Target[@nameText='HOSTILE-1']").expect("parse");
        assert_eq!(filter.class_name, "Target");
        assert_eq!(filter.predicates.len(), 1);
        assert_eq!(filter.predicates[0].property_name, "nameText");
        assert_eq!(filter.predicates[0].value, "HOSTILE-1");
    }

    #[test]
    fn matches_instance_properties() {
        let filter = parse_filter("//Target[nameText=\"FRIEND-1\"]").expect("parse");
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        let instance = MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "FRIEND-1"));
        assert!(instance_matches(&instance, &filter));
    }
}
