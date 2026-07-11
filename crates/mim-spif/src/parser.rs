use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use crate::policy::{SpifCategory, SpifCategoryType, SpifPolicy, SpifValidation};

/// Parse an XML-SPIF policy document per ADatP-4774.1 / ISO 29008.
pub fn parse_spif_xml(data: &str) -> Result<SpifPolicy, String> {
    let mut reader = Reader::from_str(data);
    reader.config_mut().trim_text(true);

    let mut policy_id = String::new();
    let mut policy_oid = None;
    let mut allowed_classifications = Vec::new();
    let mut categories = Vec::new();
    let mut validations = Vec::new();

    let mut buf = Vec::new();
    let mut current_element = String::new();
    let mut current_text = String::new();

    let mut in_classification = false;
    let mut in_category = false;
    let mut in_validation = false;
    let mut class_name = String::new();
    let mut cat_name = String::new();
    let mut cat_type = SpifCategoryType::Restrictive;
    let mut cat_values = Vec::new();
    let mut val_class = String::new();
    let mut val_category = String::new();
    let mut val_required = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                current_element = local_name(e);
                current_text.clear();
                match current_element.as_str() {
                    "securityClassification" | "classification" => {
                        in_classification = true;
                        class_name.clear();
                    }
                    "securityCategory" | "category" => {
                        in_category = true;
                        cat_name.clear();
                        cat_type = SpifCategoryType::Restrictive;
                        cat_values.clear();
                        if let Some(t) = attr_value(e, b"type").or_else(|| attr_value(e, b"tagtype")) {
                            cat_type = parse_category_type(&t);
                        }
                    }
                    "validation" => {
                        in_validation = true;
                        val_class.clear();
                        val_category.clear();
                        val_required.clear();
                    }
                    "securityPolicyId" | "policyIdentifier" => {}
                    _ => {}
                }
                if current_element == "identifier" || current_element == "name" {
                    if let Some(id) = attr_value(e, b"URL").or_else(|| attr_value(e, b"url")) {
                        policy_oid = Some(id);
                    }
                }
            }
            Ok(Event::Empty(ref e)) => {
                if let Some(id) = attr_value(e, b"URL").or_else(|| attr_value(e, b"url")) {
                    policy_oid = Some(id);
                }
            }
            Ok(Event::Text(ref e)) => {
                current_text = String::from_utf8_lossy(e.as_ref()).trim().to_owned();
            }
            Ok(Event::End(ref e)) => {
                let name = local_name_bytes(e.local_name().as_ref());
                match name.as_str() {
                    "identifier" if policy_id.is_empty() => policy_id = current_text.clone(),
                    "name" if in_classification => class_name = current_text.clone(),
                    "name" if in_category => cat_name = current_text.clone(),
                    "type" | "tagtype" if in_category => {
                        cat_type = parse_category_type(&current_text);
                    }
                    "genericValue" | "categoryName" | "value" if in_category => {
                        if !current_text.is_empty() {
                            cat_values.push(current_text.clone());
                        }
                    }
                    "classification" if in_validation => val_class = current_text.clone(),
                    "categoryName" if in_validation => val_category = current_text.clone(),
                    "requiredValue" | "genericValue" if in_validation => {
                        if !current_text.is_empty() {
                            val_required.push(current_text.clone());
                        }
                    }
                    "securityClassification" | "classification" if in_classification => {
                        if !class_name.is_empty() {
                            allowed_classifications.push(class_name.clone());
                        }
                        in_classification = false;
                    }
                    "securityCategory" | "category" if in_category => {
                        if !cat_name.is_empty() {
                            categories.push(SpifCategory {
                                name: cat_name.clone(),
                                category_type: cat_type,
                                allowed_values: cat_values.clone(),
                            });
                        }
                        in_category = false;
                    }
                    "validation" if in_validation => {
                        if !val_class.is_empty() && !val_category.is_empty() {
                            validations.push(SpifValidation {
                                classification: val_class.clone(),
                                category_name: val_category.clone(),
                                required_any_of: val_required.clone(),
                            });
                        }
                        in_validation = false;
                    }
                    _ => {}
                }
                current_text.clear();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => return Err(err.to_string()),
        }
        buf.clear();
    }

    if policy_id.is_empty() {
        return Err("SPIF policy missing securityPolicyId/identifier".into());
    }

    Ok(SpifPolicy {
        policy_id,
        policy_oid,
        allowed_classifications,
        categories,
        validations,
    })
}

fn parse_category_type(value: &str) -> SpifCategoryType {
    match value.to_ascii_lowercase().as_str() {
        "permissive" => SpifCategoryType::Permissive,
        "informative" => SpifCategoryType::Informative,
        _ => SpifCategoryType::Restrictive,
    }
}

fn local_name(e: &BytesStart<'_>) -> String {
    String::from_utf8_lossy(e.local_name().as_ref()).into_owned()
}

fn local_name_bytes(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn attr_value(e: &BytesStart<'_>, key: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(|attr| attr.ok())
        .find(|attr| attr.key.as_ref() == key || attr.key.local_name().as_ref() == key)
        .and_then(|attr| String::from_utf8(attr.value.into_owned()).ok())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_acme_policy() {
        let policy = parse_spif_xml(include_str!("../fixtures/acme-policy.xml")).expect("parse");
        assert_eq!(policy.policy_id, "ACME");
        assert!(policy.allowed_classifications.contains(&"CONFIDENTIAL".into()));
        assert!(!policy.validations.is_empty());
    }
}
