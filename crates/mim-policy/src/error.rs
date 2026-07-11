use thiserror::Error;

pub type PolicyResult<T> = Result<T, PolicyError>;

#[derive(Debug, Error, PartialEq)]
pub enum PolicyError {
    #[error("access denied: {0}")]
    Denied(String),

    #[error("policy not found: {0}")]
    NotFound(String),

    #[error("invalid policy: {0}")]
    Invalid(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<mim_labeling::LabelError> for PolicyError {
    fn from(value: mim_labeling::LabelError) -> Self {
        match value {
            mim_labeling::LabelError::Validation(msg) => Self::Validation(msg),
            mim_labeling::LabelError::InvalidDomain(msg) => Self::Invalid(msg),
            mim_labeling::LabelError::CrossDomain(msg) => Self::Denied(msg),
            other => Self::Validation(other.to_string()),
        }
    }
}

impl From<PolicyError> for mim_labeling::LabelError {
    fn from(value: PolicyError) -> Self {
        match value {
            PolicyError::Denied(msg) => Self::CrossDomain(msg),
            PolicyError::Validation(msg) => Self::Validation(msg),
            PolicyError::Invalid(msg) => Self::InvalidPolicy(msg),
            other => Self::Validation(other.to_string()),
        }
    }
}
