use mim_labeling::{ConfidentialityLabel, LabelError, LabelResult};

use crate::json;
use crate::xsd;
use crate::xml;

/// Encoding format for STANAG 4774 labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stanag4774Format {
    Xml,
    JsonStructured,
}

/// Codec for STANAG 4774 confidentiality labels.
#[derive(Clone, Debug, Default)]
pub struct Stanag4774Codec;

impl Stanag4774Codec {
    pub fn new() -> Self {
        Self
    }

    pub fn serialize(
        &self,
        label: &ConfidentialityLabel,
        format: Stanag4774Format,
    ) -> LabelResult<String> {
        label.validate()?;
        match format {
            Stanag4774Format::Xml => xml::serialize(label),
            Stanag4774Format::JsonStructured => json::serialize(label),
        }
    }

    pub fn deserialize(
        &self,
        data: &str,
        format: Stanag4774Format,
    ) -> LabelResult<ConfidentialityLabel> {
        self.deserialize_with_options(data, format, true)
    }

    pub fn deserialize_with_options(
        &self,
        data: &str,
        format: Stanag4774Format,
        validate_xsd: bool,
    ) -> LabelResult<ConfidentialityLabel> {
        if validate_xsd && format == Stanag4774Format::Xml {
            xsd::validate_stanag4774_xsd(data).map_err(|err| {
                LabelError::Validation(format!("STANAG 4774 XSD validation failed: {err}"))
            })?;
        }
        let label = match format {
            Stanag4774Format::Xml => xml::deserialize(data)?,
            Stanag4774Format::JsonStructured => json::deserialize(data)?,
        };
        label.validate()?;
        Ok(label)
    }

    pub fn round_trip(
        &self,
        label: &ConfidentialityLabel,
        format: Stanag4774Format,
    ) -> LabelResult<ConfidentialityLabel> {
        let encoded = self.serialize(label, format)?;
        self.deserialize(&encoded, format)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::TimeZone;
    use mim_labeling::{CategoryMarking, ClassificationLevel, LabelPolicy};

    use super::*;

    fn sample_label() -> ConfidentialityLabel {
        ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec![
                "USA".into(),
                "GBR".into(),
            ]))
            .with_creation_time(chrono::Utc.with_ymd_and_hms(2026, 7, 11, 6, 15, 0).unwrap())
    }

    #[test]
    fn xml_round_trip() {
        let codec = Stanag4774Codec::new();
        let restored = codec
            .deserialize_with_options(
                &codec
                    .serialize(&sample_label(), Stanag4774Format::Xml)
                    .expect("serialize"),
                Stanag4774Format::Xml,
                true,
            )
            .expect("round trip");
        assert_eq!(restored.classification, ClassificationLevel::Secret);
        assert_eq!(restored.releasable_countries(), vec!["USA", "GBR"]);
    }

    #[test]
    fn json_round_trip() {
        let codec = Stanag4774Codec::new();
        let restored = codec
            .round_trip(&sample_label(), Stanag4774Format::JsonStructured)
            .expect("round trip");
        assert_eq!(restored.policy.identifier, "NATO");
    }
}
