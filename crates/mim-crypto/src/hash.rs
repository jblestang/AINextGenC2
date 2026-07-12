use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::provider::selected_provider;

/// SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    selected_provider().hash_sha256(data)
}

/// Base64-encoded SHA-256 digest (NMBS payload digest format).
pub fn sha256_base64(data: &[u8]) -> String {
    STANDARD.encode(sha256(data))
}

/// Lowercase hex-encoded SHA-256 digest (certificate fingerprint format).
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
