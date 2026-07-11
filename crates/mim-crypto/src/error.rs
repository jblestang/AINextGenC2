use thiserror::Error;

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Debug, Error, PartialEq)]
pub enum CryptoError {
    #[error("cryptographic operation failed: {0}")]
    Operation(String),

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}
