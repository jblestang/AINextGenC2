//! Zero Trust Data Format (ZTDF) packaging for MIM exchanges.
//!
//! Implements OpenTDF manifest structure with mandatory STANAG 4774 label
//! assertions and STANAG 4778 cryptographic bindings per ACP-240 supplements.

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

pub mod assertion;
pub mod manifest;
pub mod package;

pub use manifest::{ZtdfManifest, ZtdfSpecVersion};
pub use package::ZtdfPackage;
