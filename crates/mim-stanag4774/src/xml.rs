use chrono::{DateTime, Utc};
use mim_labeling::{
    CategoryMarking, CategoryType, ClassificationLevel, ConfidentialityLabel, LabelError,
    LabelPolicy, LabelResult,
};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Reader;
use quick_xml::Writer;
use serde_json::{json, Value};

use crate::NAMESPACE;

const LABEL_WRAPPERS: &[&str] = &[
    "ConfidentialityLabel",
    "originatorConfidentialityLabel",
    "metadataConfidentialityLabel",
    "alternativeConfidentialityLabel",
];

pub fn serialize(label: &ConfidentialityLabel) -> LabelResult<String> {
    let mut writer = Writer::new(Vec::new());
    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .map_err(|e| LabelError::Serialization(e.to_string()))?;

    let mut root = BytesStart::new("ConfidentialityLabel");
    root.push_attribute(("xmlns", NAMESPACE));
    if let Some(creation) = label.creation_time {
        root.push_attribute(("CreationTime", creation.to_rfc3339().as_str()));
    }
    if let Some(review) = label.review_date_time {
        root.push_attribute(("ReviewDateTime", review.to_rfc3339().as_str()));
    }
    writer
        .write_event(Event::Start(root))
        .map_err(|e| LabelError::Serialization(e.to_string()))?;

    write_confidentiality_information(&mut writer, label)?;

    for alt in &label.alternative_labels {
        writer
            .write_event(Event::Start(BytesStart::new(
                "alternativeConfidentialityLabel",
            )))
            .map_err(|e| LabelError::Serialization(e.to_string()))?;
        write_confidentiality_information(&mut writer, alt)?;
        writer
            .write_event(Event::End(BytesEnd::new(
                "alternativeConfidentialityLabel",
            )))
            .map_err(|e| LabelError::Serialization(e.to_string()))?;
    }

    writer
        .write_event(Event::End(BytesEnd::new("ConfidentialityLabel")))
        .map_err(|e| LabelError::Serialization(e.to_string()))?;

    String::from_utf8(writer.into_inner()).map_err(|e| LabelError::Serialization(e.to_string()))
}

fn write_confidentiality_information(
    writer: &mut Writer<Vec<u8>>,
    label: &ConfidentialityLabel,
) -> LabelResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("ConfidentialityInformation")))
        .map_err(|e| LabelError::Serialization(e.to_string()))?;

    if let Some(oid) = &label.policy.oid {
        let mut policy = BytesStart::new("PolicyIdentifier");
        policy.push_attribute(("URL", oid.as_str()));
        writer
            .write_event(Event::Start(policy))
            .map_err(|e| LabelError::Serialization(e.to_string()))?;
        writer
            .write_event(Event::Text(quick_xml::events::BytesText::new(
                &label.policy.identifier,
            )))
            .map_err(|e| LabelError::Serialization(e.to_string()))?;
        writer
            .write_event(Event::End(BytesEnd::new("PolicyIdentifier")))
            .map_err(|e| LabelError::Serialization(e.to_string()))?;
    } else {
        write_text_element(writer, "PolicyIdentifier", &label.policy.identifier)?;
    }

    write_text_element(
        writer,
        "Classification",
        label.classification.as_stanag_str(),
    )?;

    if let Some(privacy) = &label.privacy_mark {
        write_text_element(writer, "PrivacyMark", privacy)?;
    }

    if let Some(colour) = &label.colour {
        write_text_element(writer, "Colour", colour)?;
    }

    if let Some(marking) = &label.marking_data {
        write_text_element(writer, "MarkingData", marking)?;
    }

    for category in &label.categories {
        let mut cat = BytesStart::new("Category");
        cat.push_attribute(("TagName", category.tag_name.as_str()));
        cat.push_attribute(("Type", category_type_to_str(category.category_type)));
        writer
            .write_event(Event::Start(cat))
            .map_err(|e| LabelError::Serialization(e.to_string()))?;

        for value in &category.values {
            write_text_element(writer, "GenericValue", value)?;
        }

        writer
            .write_event(Event::End(BytesEnd::new("Category")))
            .map_err(|e| LabelError::Serialization(e.to_string()))?;
    }

    writer
        .write_event(Event::End(BytesEnd::new("ConfidentialityInformation")))
        .map_err(|e| LabelError::Serialization(e.to_string()))?;
    Ok(())
}

fn category_type_to_str(category_type: CategoryType) -> &'static str {
    match category_type {
        CategoryType::Restrictive => "RESTRICTIVE",
        CategoryType::Permissive => "PERMISSIVE",
        CategoryType::Informative => "INFORMATIVE",
    }
}

fn parse_category_type(value: &str) -> CategoryType {
    if value.eq_ignore_ascii_case("RESTRICTIVE") {
        CategoryType::Restrictive
    } else if value.eq_ignore_ascii_case("INFORMATIVE") {
        CategoryType::Informative
    } else {
        CategoryType::Permissive
    }
}

fn write_text_element(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    value: &str,
) -> LabelResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new(name)))
        .map_err(|e| LabelError::Serialization(e.to_string()))?;
    writer
        .write_event(Event::Text(quick_xml::events::BytesText::new(value)))
        .map_err(|e| LabelError::Serialization(e.to_string()))?;
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(|e| LabelError::Serialization(e.to_string()))
}

pub fn deserialize(data: &str) -> LabelResult<ConfidentialityLabel> {
    let mut reader = Reader::from_str(data);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut policy = String::new();
    let mut policy_oid = None;
    let mut classification = String::new();
    let mut privacy_mark = None;
    let mut colour = None;
    let mut marking_data = None;
    let mut categories = Vec::new();
    let mut alternative_labels = Vec::new();
    let mut creation_time = None;
    let mut review_date_time = None;

    let mut current_category_tag = String::new();
    let mut current_category_type = CategoryType::Permissive;
    let mut current_category_values = Vec::new();
    let mut in_category = false;
    let mut in_alternative = false;
    let mut alt_policy = String::new();
    let mut alt_policy_oid: Option<String> = None;
    let mut alt_classification = String::new();
    let mut alt_privacy = None;
    let mut alt_colour = None;
    let mut alt_marking = None;
    let mut alt_categories = Vec::new();
    let mut current_element = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if LABEL_WRAPPERS.contains(&name.as_str()) {
                    if name == "alternativeConfidentialityLabel" {
                        in_alternative = true;
                        alt_policy.clear();
                        alt_policy_oid = None;
                        alt_classification.clear();
                        alt_privacy = None;
                        alt_colour = None;
                        alt_marking = None;
                        alt_categories.clear();
                    }
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        let val = String::from_utf8_lossy(&attr.value);
                        match key.as_ref() {
                            "CreationTime" => {
                                creation_time = Some(parse_datetime(&val)?);
                            }
                            "ReviewDateTime" => {
                                review_date_time = Some(parse_datetime(&val)?);
                            }
                            _ => {}
                        }
                    }
                } else if name == "PolicyIdentifier" {
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        let val = String::from_utf8_lossy(&attr.value);
                        if key.as_ref() == "URL" || key.as_ref() == "URI" {
                            policy_oid = Some(val.into_owned());
                        }
                    }
                } else if name == "Category" {
                    in_category = true;
                    current_category_values.clear();
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        let val = String::from_utf8_lossy(&attr.value);
                        match key.as_ref() {
                            "TagName" => current_category_tag = val.into_owned(),
                            "Type" => current_category_type = parse_category_type(&val),
                            _ => {}
                        }
                    }
                }
                current_element = name;
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().map_err(|err| LabelError::Parse(err.to_string()))?;
                match current_element.as_str() {
                    "PolicyIdentifier" => policy = text.into_owned(),
                    "Classification" => {
                        if in_alternative {
                            alt_classification = text.into_owned();
                        } else {
                            classification = text.into_owned();
                        }
                    }
                    "PrivacyMark" => {
                        if in_alternative {
                            alt_privacy = Some(text.into_owned());
                        } else {
                            privacy_mark = Some(text.into_owned());
                        }
                    }
                    "Colour" => {
                        if in_alternative {
                            alt_colour = Some(text.into_owned());
                        } else {
                            colour = Some(text.into_owned());
                        }
                    }
                    "MarkingData" => {
                        if in_alternative {
                            alt_marking = Some(text.into_owned());
                        } else {
                            marking_data = Some(text.into_owned());
                        }
                    }
                    "GenericValues" | "GenericValue" if in_category => {
                        current_category_values.push(text.into_owned());
                    }
                    "CreationDateTime" | "CreationTime" => {
                        creation_time = Some(parse_datetime(&text)?);
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.name().as_ref().to_vec();
                let name = String::from_utf8_lossy(&local_name);
                if name == "Category" && in_category {
                    categories.push(CategoryMarking {
                        tag_name: current_category_tag.clone(),
                        category_type: current_category_type,
                        values: current_category_values.clone(),
                    });
                    in_category = false;
                } else if name == "Category" && in_alternative {
                    alt_categories.push(CategoryMarking {
                        tag_name: current_category_tag.clone(),
                        category_type: current_category_type,
                        values: current_category_values.clone(),
                    });
                    in_category = false;
                } else if name == "alternativeConfidentialityLabel" && in_alternative {
                    if !alt_classification.is_empty() {
                        let mut alt_policy_obj = LabelPolicy::new(if alt_policy.is_empty() {
                            "NATO".into()
                        } else {
                            alt_policy.clone()
                        });
                        if let Some(oid) = alt_policy_oid.clone() {
                            alt_policy_obj = alt_policy_obj.with_oid(oid);
                        }
                        let mut alt_label = ConfidentialityLabel::new(
                            alt_policy_obj,
                            ClassificationLevel::parse(&alt_classification)?,
                        );
                        alt_label.privacy_mark = alt_privacy.clone();
                        alt_label.colour = alt_colour.clone();
                        alt_label.marking_data = alt_marking.clone();
                        alt_label.categories = alt_categories.clone();
                        alternative_labels.push(alt_label);
                    }
                    in_alternative = false;
                }
                current_element.clear();
            }
            Ok(_) => {}
            Err(err) => return Err(LabelError::Parse(err.to_string())),
        }
        buf.clear();
    }

    if policy.is_empty() {
        policy = "NATO".to_owned();
    }
    if classification.is_empty() {
        return Err(LabelError::Validation(
            "Classification element is mandatory".into(),
        ));
    }

    let mut label_policy = LabelPolicy::new(policy);
    if let Some(oid) = policy_oid {
        label_policy = label_policy.with_oid(oid);
    }

    let mut label =
        ConfidentialityLabel::new(label_policy, ClassificationLevel::parse(&classification)?);
    label.privacy_mark = privacy_mark;
    label.colour = colour;
    label.marking_data = marking_data;
    label.categories = categories;
    label.alternative_labels = alternative_labels;
    label.creation_time = creation_time;
    label.review_date_time = review_date_time;
    Ok(label)
}

fn parse_datetime(value: &str) -> LabelResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| LabelError::Parse(e.to_string()))
}

pub fn to_json_value(label: &ConfidentialityLabel) -> Value {
    let mut info = serde_json::Map::new();
    info.insert(
        "PolicyIdentifier".to_owned(),
        json!(label.policy.identifier),
    );
    info.insert(
        "Classification".to_owned(),
        json!(label.classification.as_stanag_str()),
    );
    if let Some(privacy) = &label.privacy_mark {
        info.insert("PrivacyMark".to_owned(), json!(privacy));
    }
    if !label.categories.is_empty() {
        let cats: Vec<Value> = label
            .categories
            .iter()
            .map(|c| {
                json!({
                    "TagName": c.tag_name,
                    "Type": category_type_to_str(c.category_type),
                    "GenericValues": c.values,
                })
            })
            .collect();
        info.insert("Category".to_owned(), json!(cats));
    }

    let mut root = serde_json::Map::new();
    root.insert("Xmlns".to_owned(), json!(NAMESPACE));
    root.insert("ConfidentialityInformation".to_owned(), Value::Object(info));
    if let Some(creation) = label.creation_time {
        root.insert("CreationTime".to_owned(), json!(creation.to_rfc3339()));
    }
    if let Some(review) = label.review_date_time {
        root.insert("ReviewDateTime".to_owned(), json!(review.to_rfc3339()));
    }
    Value::Object(root)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_adatp_table17_nato_vector() {
        let xml = include_str!("../fixtures/adatp/nato-4774-17-1.nato");
        let label = deserialize(xml).expect("parse");
        assert_eq!(label.policy.identifier, "NATO");
        assert_eq!(label.classification, ClassificationLevel::Unclassified);
        assert_eq!(label.categories.len(), 2);
    }
}
