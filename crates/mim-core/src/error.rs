use thiserror::Error;

/// Result type used throughout the MIM stack.
pub type MimResult<T> = Result<T, MimError>;

/// Unified error type for MIM operations.
#[derive(Debug, Error, PartialEq)]
pub enum MimError {
    #[error("invalid semantic id: {0}")]
    InvalidSemanticId(String),

    #[error("invalid MIM URI: {0}")]
    InvalidUri(String),

    #[error("invalid representation term: {0}")]
    InvalidRepresentationTerm(String),

    #[error("invalid nil reason: {0}")]
    InvalidNilReason(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("model error: {0}")]
    Model(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("compliance error: {0}")]
    Compliance(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for MimError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<serde_json::Error> for MimError {
    fn from(value: serde_json::Error) -> Self {
        Self::Parse(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_stable() {
        let err = MimError::InvalidSemanticId("bad".into());
        assert_eq!(err.to_string(), "invalid semantic id: bad");
    }
}
