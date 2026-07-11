use thiserror::Error;

pub type LabelResult<T> = Result<T, LabelError>;

#[derive(Debug, Error, PartialEq)]
pub enum LabelError {
    #[error("invalid classification: {0}")]
    InvalidClassification(String),

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("invalid domain: {0}")]
    InvalidDomain(String),

    #[error("label validation error: {0}")]
    Validation(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("binding error: {0}")]
    Binding(String),

    #[error("cross-domain policy violation: {0}")]
    CrossDomain(String),

    #[error("compliance error: {0}")]
    Compliance(String),
}

impl From<LabelError> for mim_core::MimError {
    fn from(value: LabelError) -> Self {
        match value {
            LabelError::Parse(msg) => Self::Parse(msg),
            LabelError::Serialization(msg) => Self::Serialization(msg),
            LabelError::Validation(msg) => Self::Validation(msg),
            LabelError::Compliance(msg) => Self::Compliance(msg),
            other => Self::Validation(other.to_string()),
        }
    }
}
