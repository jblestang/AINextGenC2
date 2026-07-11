use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::MimError;

impl<T> Default for Nillable<T> {
    fn default() -> Self {
        Self::Absent
    }
}

/// Reason why a nillable MIM property has no value.
///
/// Inspired by GML NilReasonType but tailored for MIM operational semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NilReason {
    /// No appropriate code list entry; extension value may be provided separately.
    Inapplicable,
    /// Information does not make sense in the given context.
    Missing,
    /// Value not available now but may become available later.
    Unknown,
    /// Value exists but is withheld (e.g. security restrictions).
    Withheld,
    /// Value not known to sender but likely exists.
    UnknownSender,
    /// Value will be available later.
    Pending,
}

impl NilReason {
    pub const ALL: &'static [Self] = &[
        Self::Inapplicable,
        Self::Missing,
        Self::Unknown,
        Self::Withheld,
        Self::UnknownSender,
        Self::Pending,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inapplicable => "inapplicable",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
            Self::Withheld => "withheld",
            Self::UnknownSender => "unknownSender",
            Self::Pending => "pending",
        }
    }
}

impl FromStr for NilReason {
    type Err = MimError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "inapplicable" => Ok(Self::Inapplicable),
            "missing" => Ok(Self::Missing),
            "unknown" => Ok(Self::Unknown),
            "withheld" => Ok(Self::Withheld),
            "unknownSender" | "unknown_sender" => Ok(Self::UnknownSender),
            "pending" => Ok(Self::Pending),
            other => Err(MimError::InvalidNilReason(other.to_owned())),
        }
    }
}

impl fmt::Display for NilReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A MIM property value that may be present, absent, or nil with reason.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Nillable<T> {
    Value { value: T },
    Nil { reason: NilReason },
    Absent,
}

impl<T> Nillable<T> {
    pub fn value(value: T) -> Self {
        Self::Value { value }
    }

    pub fn nil(reason: NilReason) -> Self {
        Self::Nil { reason }
    }

    pub fn is_present(&self) -> bool {
        matches!(self, Self::Value { .. })
    }

    pub fn as_option(&self) -> Option<&T> {
        match self {
            Self::Value { value } => Some(value),
            Self::Nil { .. } | Self::Absent => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_nil_reason_variants() {
        assert_eq!(
            NilReason::from_str("withheld").expect("valid"),
            NilReason::Withheld
        );
        assert_eq!(
            NilReason::from_str("unknownSender").expect("valid"),
            NilReason::UnknownSender
        );
    }

    #[test]
    fn nillable_value_presence() {
        let present = Nillable::value(42);
        assert!(present.is_present());
        assert_eq!(present.as_option(), Some(&42));

        let nil = Nillable::<i32>::nil(NilReason::Missing);
        assert!(!nil.is_present());
        assert_eq!(nil.as_option(), None);
    }
}
