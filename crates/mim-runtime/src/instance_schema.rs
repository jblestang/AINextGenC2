use serde_json::Value;

use crate::instance::MimInstance;

/// Structural JSON schema validation for MIM instances on the wire (MIP4-IES profile).
pub fn validate_instance_json_schema(value: &Value) -> Result<(), String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "instance root must be a JSON object".to_string())?;

    require_string_field(obj, "oid")?;
    require_string_field(obj, "className")?;
    require_string_field(obj, "classSemanticId")?;

    let properties = obj
        .get("properties")
        .ok_or_else(|| "missing properties array".to_string())?;
    if !properties.is_array() {
        return Err("properties must be an array".to_string());
    }

    for property in properties.as_array().into_iter().flatten() {
        validate_property_object(property)?;
    }

    Ok(())
}

pub fn validate_instance_json_schema_str(json: &str) -> Result<(), String> {
    let value: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    validate_instance_json_schema(&value)
}

pub fn validate_serialized_instance(instance: &MimInstance) -> Result<(), String> {
    let json = serde_json::to_value(instance).map_err(|e| e.to_string())?;
    validate_instance_json_schema(&json)
}

fn validate_property_object(value: &Value) -> Result<(), String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "property entry must be an object".to_string())?;
    require_string_field(obj, "name")?;
    if !obj.contains_key("value") {
        return Err("property missing value field".to_string());
    }
    Ok(())
}

fn require_string_field(obj: &serde_json::Map<String, Value>, key: &str) -> Result<(), String> {
    match obj.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(()),
        Some(_) => Err(format!("field '{key}' must be a non-empty string")),
        None => Err(format!("missing required field '{key}'")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::SemanticId;

    use super::*;
    use crate::instance::{MimInstance, PropertyValue};

    #[test]
    fn accepts_valid_instance_json() {
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        let instance = MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "X"));
        validate_serialized_instance(&instance).expect("valid");
    }

    #[test]
    fn rejects_missing_oid() {
        let bad = serde_json::json!({
            "className": "Target",
            "classSemanticId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "properties": []
        });
        assert!(validate_instance_json_schema(&bad).is_err());
    }
}
