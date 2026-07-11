use thiserror::Error;

pub type TransportResult<T> = Result<T, TransportError>;

#[derive(Debug, Error, PartialEq)]
pub enum TransportError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("object not found: {0}")]
    NotFound(String),

    #[error("object inactive: {0}")]
    Inactive(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("unsupported operation: {0}")]
    Unsupported(String),
}

impl From<TransportError> for mim_core::MimError {
    fn from(value: TransportError) -> Self {
        match value {
            TransportError::NotFound(msg) => Self::NotFound(msg),
            TransportError::Serialization(msg) => Self::Serialization(msg),
            TransportError::Validation(msg) => Self::Validation(msg),
            other => Self::Validation(other.to_string()),
        }
    }
}

impl From<mim_core::MimError> for TransportError {
    fn from(value: mim_core::MimError) -> Self {
        match value {
            mim_core::MimError::NotFound(msg) => Self::NotFound(msg),
            mim_core::MimError::Serialization(msg) => Self::Serialization(msg),
            mim_core::MimError::Validation(msg) => Self::Validation(msg),
            other => Self::Validation(other.to_string()),
        }
    }
}
