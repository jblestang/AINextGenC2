//! STANAG 4774 confidentiality metadata label syntax (ADatP-4774).
//!
//! Supports XML and JSON-structured encodings per
//! `urn:nato:stanag:4774:confidentialitymetadatalabel:1:0`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented
)]

pub mod codec;
pub mod json;
pub mod xsd;
pub mod xml;

pub use codec::{Stanag4774Codec, Stanag4774Format};
pub use xsd::validate_stanag4774_xsd;

/// STANAG 4774 XML namespace URI.
pub const NAMESPACE: &str = "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0";
