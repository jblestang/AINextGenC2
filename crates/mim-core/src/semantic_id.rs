use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{MimError, MimResult};

/// RFC 4122 UUID identifying a MIM model element across versions.
///
/// Semantic IDs establish semantic equivalence between model elements in
/// different MIM releases regardless of qualified name changes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SemanticId(Uuid);

impl SemanticId {
    /// Parse a semantic ID from its canonical string form.
    pub fn parse(value: &str) -> MimResult<Self> {
        let trimmed = value.trim();
        let uuid = Uuid::parse_str(trimmed)
            .map_err(|_| MimError::InvalidSemanticId(trimmed.to_owned()))?;
        Ok(Self(uuid))
    }

    /// Create from an existing UUID value.
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Access the underlying UUID.
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Canonical lowercase hyphenated representation.
    pub fn as_str(&self) -> String {
        self.0.hyphenated().to_string()
    }

    /// MIM linked-data semantic ID URL.
    pub fn linked_data_url(&self) -> String {
        format!(
            "https://www.mimworld.org/mim/semanticID/{}",
            self.as_str()
        )
    }
}

impl FromStr for SemanticId {
    type Err = MimError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for SemanticId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Debug for SemanticId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SemanticId({})", self.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const UNIT_RANGE_CODE_ID: &str = "080de7fa-fc13-4201-8364-0aa47e5c10bc";

    #[test]
    fn parses_known_mim_semantic_id() {
        let id = SemanticId::parse(UNIT_RANGE_CODE_ID).expect("valid id");
        assert_eq!(id.to_string(), UNIT_RANGE_CODE_ID);
    }

    #[test]
    fn rejects_invalid_semantic_id() {
        let err = SemanticId::parse("not-a-uuid").expect_err("must fail");
        assert!(matches!(err, MimError::InvalidSemanticId(_)));
    }

    #[test]
    fn linked_data_url_format() {
        let id = SemanticId::parse(UNIT_RANGE_CODE_ID).expect("valid id");
        assert_eq!(
            id.linked_data_url(),
            "https://www.mimworld.org/mim/semanticID/080de7fa-fc13-4201-8364-0aa47e5c10bc"
        );
    }

    #[test]
    fn serde_roundtrip() {
        let id = SemanticId::parse(UNIT_RANGE_CODE_ID).expect("valid id");
        let json = serde_json::to_string(&id).expect("serialize");
        let restored: SemanticId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, restored);
    }
}
