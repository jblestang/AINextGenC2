use std::fmt;
use std::str::FromStr;

use mim_core::{MimError, MimResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Globally unique object identifier for MIM instances (MIP WS/OO XSD pattern).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectIdentifier(String);

impl ObjectIdentifier {
    pub fn new(value: impl Into<String>) -> MimResult<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(MimError::Validation(
                "object identifier must not be empty".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn generate_urn() -> Self {
        Self(format!("urn:uuid:{}", Uuid::new_v4().hyphenated()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ObjectIdentifier {
    type Err = MimError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectIdentifier({})", self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_oid() {
        let err = ObjectIdentifier::new("").expect_err("must fail");
        assert!(matches!(err, MimError::Validation(_)));
    }

    #[test]
    fn generates_urn_uuid_oid() {
        let oid = ObjectIdentifier::generate_urn();
        assert!(oid.as_str().starts_with("urn:uuid:"));
    }
}
