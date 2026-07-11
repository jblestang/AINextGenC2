use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::MimError;

/// UN/CEFACT Core Component representation terms used by MIM attribute stereotypes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RepresentationTerm {
    Identifier,
    Name,
    Text,
    Indicator,
    Speed,
    Dimension,
    Duration,
    Quantity,
    Amount,
    Percent,
    Measure,
    Date,
    Time,
    DateTime,
    Graphic,
    Sound,
    Video,
    Value,
    Code,
    Ratio,
    Numeric,
}

impl RepresentationTerm {
    pub const ALL: &'static [Self] = &[
        Self::Identifier,
        Self::Name,
        Self::Text,
        Self::Indicator,
        Self::Speed,
        Self::Dimension,
        Self::Duration,
        Self::Quantity,
        Self::Amount,
        Self::Percent,
        Self::Measure,
        Self::Date,
        Self::Time,
        Self::DateTime,
        Self::Graphic,
        Self::Sound,
        Self::Video,
        Self::Value,
        Self::Code,
        Self::Ratio,
        Self::Numeric,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identifier => "identifier",
            Self::Name => "name",
            Self::Text => "text",
            Self::Indicator => "indicator",
            Self::Speed => "speed",
            Self::Dimension => "dimension",
            Self::Duration => "duration",
            Self::Quantity => "quantity",
            Self::Amount => "amount",
            Self::Percent => "percent",
            Self::Measure => "measure",
            Self::Date => "date",
            Self::Time => "time",
            Self::DateTime => "dateTime",
            Self::Graphic => "graphic",
            Self::Sound => "sound",
            Self::Video => "video",
            Self::Value => "value",
            Self::Code => "code",
            Self::Ratio => "ratio",
            Self::Numeric => "numeric",
        }
    }
}

impl FromStr for RepresentationTerm {
    type Err = MimError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "identifier" => Ok(Self::Identifier),
            "name" => Ok(Self::Name),
            "text" => Ok(Self::Text),
            "indicator" => Ok(Self::Indicator),
            "speed" => Ok(Self::Speed),
            "dimension" => Ok(Self::Dimension),
            "duration" => Ok(Self::Duration),
            "quantity" => Ok(Self::Quantity),
            "amount" => Ok(Self::Amount),
            "percent" => Ok(Self::Percent),
            "measure" => Ok(Self::Measure),
            "date" => Ok(Self::Date),
            "time" => Ok(Self::Time),
            "dateTime" | "datetime" => Ok(Self::DateTime),
            "graphic" => Ok(Self::Graphic),
            "sound" => Ok(Self::Sound),
            "video" => Ok(Self::Video),
            "value" => Ok(Self::Value),
            "code" => Ok(Self::Code),
            "ratio" => Ok(Self::Ratio),
            "numeric" => Ok(Self::Numeric),
            other => Err(MimError::InvalidRepresentationTerm(other.to_owned())),
        }
    }
}

impl fmt::Display for RepresentationTerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Metadata attached to MIM attributes based on their representation term.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RepresentationMetadata {
    pub unit_of_measure: Option<String>,
    pub minimum_value: Option<String>,
    pub maximum_value: Option<String>,
    pub identifier_scheme: Option<String>,
    pub pattern: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_speed_representation_term() {
        let term = RepresentationTerm::from_str("speed").expect("valid");
        assert_eq!(term, RepresentationTerm::Speed);
    }

    #[test]
    fn rejects_unknown_representation_term() {
        let err = RepresentationTerm::from_str("velocity").expect_err("must fail");
        assert!(matches!(err, MimError::InvalidRepresentationTerm(_)));
    }
}
