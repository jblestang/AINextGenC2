use mim_labeling::{
    CategoryMarking, CategoryType, ClassificationLevel, ConfidentialityLabel, LabelError,
    LabelPolicy, LabelResult,
};
use serde_json::Value;

use crate::NAMESPACE;
use crate::xml;

pub fn serialize(label: &ConfidentialityLabel) -> LabelResult<String> {
    serde_json::to_string_pretty(&xml::to_json_value(label))
        .map_err(|e| LabelError::Serialization(e.to_string()))
}

pub fn deserialize(data: &str) -> LabelResult<ConfidentialityLabel> {
    let value: Value = serde_json::from_str(data).map_err(|e| LabelError::Parse(e.to_string()))?;
    parse_json_value(&value)
}

fn parse_json_value(value: &Value) -> LabelResult<ConfidentialityLabel> {
    let info = value
        .get("ConfidentialityInformation")
        .ok_or_else(|| LabelError::Parse("missing ConfidentialityInformation".into()))?;

    let policy = info
        .get("PolicyIdentifier")
        .and_then(Value::as_str)
        .unwrap_or("NATO")
        .to_owned();

    let classification = info
        .get("Classification")
        .and_then(Value::as_str)
        .ok_or_else(|| LabelError::Validation("missing Classification".into()))?;

    let mut label = ConfidentialityLabel::new(
        LabelPolicy::new(policy),
        ClassificationLevel::parse(classification)?,
    );

    if let Some(privacy) = info.get("PrivacyMark").and_then(Value::as_str) {
        label.privacy_mark = Some(privacy.to_owned());
    }

    if let Some(category) = info.get("Category") {
        if let Some(array) = category.as_array() {
            for item in array {
                label.categories.push(parse_category(item)?);
            }
        } else {
            label.categories.push(parse_category(category)?);
        }
    }

    if let Some(creation) = value.get("CreationTime").and_then(Value::as_str) {
        label.creation_time = Some(
            chrono::DateTime::parse_from_rfc3339(creation)
                .map_err(|e| LabelError::Parse(e.to_string()))?
                .with_timezone(&chrono::Utc),
        );
    }

    if let Some(review) = value.get("ReviewDateTime").and_then(Value::as_str) {
        label.review_date_time = Some(
            chrono::DateTime::parse_from_rfc3339(review)
                .map_err(|e| LabelError::Parse(e.to_string()))?
                .with_timezone(&chrono::Utc),
        );
    }

    let _ = value
        .get("Xmlns")
        .and_then(Value::as_str)
        .filter(|ns| *ns == NAMESPACE);

    Ok(label)
}

fn parse_category(value: &Value) -> LabelResult<CategoryMarking> {
    let tag_name = value
        .get("TagName")
        .and_then(Value::as_str)
        .ok_or_else(|| LabelError::Parse("category missing TagName".into()))?
        .to_owned();

    let category_type = value
        .get("Type")
        .and_then(Value::as_str)
        .map(|t| {
            if t.eq_ignore_ascii_case("RESTRICTIVE") {
                CategoryType::Restrictive
            } else {
                CategoryType::Permissive
            }
        })
        .unwrap_or(CategoryType::Permissive);

    let values = value
        .get("GenericValues")
        .and_then(|v| {
            if let Some(arr) = v.as_array() {
                Some(
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                )
            } else {
                v.as_str().map(|s| vec![s.to_owned()])
            }
        })
        .unwrap_or_default();

    Ok(CategoryMarking {
        tag_name,
        category_type,
        values,
    })
}
