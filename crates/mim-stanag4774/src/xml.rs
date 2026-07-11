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

    write_text_element(writer, "PolicyIdentifier", &label.policy.identifier)?;
    write_text_element(
        writer,
        "Classification",
        label.classification.as_stanag_str(),
    )?;

    if let Some(privacy) = &label.privacy_mark {
        write_text_element(writer, "PrivacyMark", privacy)?;
    }

    for category in &label.categories {
        let mut cat = BytesStart::new("Category");
        cat.push_attribute(("TagName", category.tag_name.as_str()));
        cat.push_attribute((
            "Type",
            match category.category_type {
                CategoryType::Restrictive => "RESTRICTIVE",
                CategoryType::Permissive => "PERMISSIVE",
            },
        ));
        writer
            .write_event(Event::Start(cat))
            .map_err(|e| LabelError::Serialization(e.to_string()))?;

        for value in &category.values {
            write_text_element(writer, "GenericValues", value)?;
        }

        writer
            .write_event(Event::End(BytesEnd::new("Category")))
            .map_err(|e| LabelError::Serialization(e.to_string()))?;
    }

    writer
        .write_event(Event::End(BytesEnd::new("ConfidentialityInformation")))
        .map_err(|e| LabelError::Serialization(e.to_string()))
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
    let mut classification = String::new();
    let mut privacy_mark = None;
    let mut categories = Vec::new();
    let mut creation_time = None;
    let mut review_date_time = None;

    let mut current_category_tag = String::new();
    let mut current_category_type = CategoryType::Permissive;
    let mut current_category_values = Vec::new();
    let mut in_category = false;
    let mut current_element = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if name == "ConfidentialityLabel" {
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
                } else if name == "Category" {
                    in_category = true;
                    current_category_values.clear();
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        let val = String::from_utf8_lossy(&attr.value);
                        match key.as_ref() {
                            "TagName" => current_category_tag = val.into_owned(),
                            "Type" => {
                                current_category_type = if val.eq_ignore_ascii_case("RESTRICTIVE")
                                {
                                    CategoryType::Restrictive
                                } else {
                                    CategoryType::Permissive
                                };
                            }
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
                    "Classification" => classification = text.into_owned(),
                    "PrivacyMark" => privacy_mark = Some(text.into_owned()),
                    "GenericValues" if in_category => {
                        current_category_values.push(text.into_owned());
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

    let mut label = ConfidentialityLabel::new(LabelPolicy::new(policy), ClassificationLevel::parse(&classification)?);
    label.privacy_mark = privacy_mark;
    label.categories = categories;
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
                    "Type": match c.category_type {
                        CategoryType::Restrictive => "RESTRICTIVE",
                        CategoryType::Permissive => "PERMISSIVE",
                    },
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
