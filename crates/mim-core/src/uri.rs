use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{MimError, MimResult};

/// Base URL prefix for MIM linked data and qualified names.
pub const MIM_BASE_URL: &str = "https://www.mimworld.org/mim";

/// A versioned MIM qualified name path (without the base URL).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MimQualifiedName {
    pub version: String,
    pub path: String,
}

impl MimQualifiedName {
    pub fn new(version: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            path: Self::normalize_path(path.into()),
        }
    }

    pub fn parse(value: &str) -> MimResult<Self> {
        let trimmed = value.trim();
        let without_base = trimmed
            .strip_prefix(&format!("{MIM_BASE_URL}/"))
            .ok_or_else(|| MimError::InvalidUri(trimmed.to_owned()))?;

        let mut segments = without_base.splitn(2, '/');
        let version = segments
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| MimError::InvalidUri(trimmed.to_owned()))?
            .to_owned();
        let path = segments
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| MimError::InvalidUri(trimmed.to_owned()))?
            .to_owned();

        Ok(Self {
            version,
            path: Self::normalize_path(path),
        })
    }

    fn normalize_path(path: String) -> String {
        path.split('/')
            .filter(|segment| !segment.is_empty())
            .collect::<Vec<_>>()
            .join("/")
    }

    pub fn as_uri(&self) -> MimUri {
        MimUri {
            inner: format!("{MIM_BASE_URL}/{}/{}", self.version, self.path),
        }
    }
}

/// Canonical MIM element URI.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MimUri {
    inner: String,
}

impl MimUri {
    pub fn parse(value: &str) -> MimResult<Self> {
        let trimmed = value.trim();
        if !trimmed.starts_with(MIM_BASE_URL) {
            return Err(MimError::InvalidUri(trimmed.to_owned()));
        }
        // Validate structure by parsing qualified name.
        let _ = MimQualifiedName::parse(trimmed)?;
        Ok(Self {
            inner: trimmed.to_owned(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn qualified_name(&self) -> MimResult<MimQualifiedName> {
        MimQualifiedName::parse(&self.inner)
    }
}

impl FromStr for MimUri {
    type Err = MimError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for MimUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl fmt::Debug for MimUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MimUri({})", self.inner)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_line_classifier_uri() {
        let uri = MimUri::parse(
            "https://www.mimworld.org/mim/4.0.1/Classifiers/Location/Line",
        )
        .expect("valid uri");
        let qn = uri.qualified_name().expect("qualified name");
        assert_eq!(qn.version, "4.0.1");
        assert_eq!(qn.path, "Classifiers/Location/Line");
    }

    #[test]
    fn rejects_non_mim_uri() {
        let err = MimUri::parse("https://example.com/mim/1.0/Foo").expect_err("must fail");
        assert!(matches!(err, MimError::InvalidUri(_)));
    }
}
