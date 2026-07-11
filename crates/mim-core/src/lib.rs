//! Core primitives for the MIP Information Model (MIM).
//!
//! This crate provides platform-independent semantic foundations used across
//! the AINextGenC2 MIM stack: semantic identifiers, qualified URIs, UN/CEFACT
//! representation terms, nil-reason handling, and a zero-panic error model.

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

pub mod error;
pub mod nil_reason;
pub mod representation;
pub mod semantic_id;
pub mod uri;

pub use error::{MimError, MimResult};
pub use nil_reason::{Nillable, NilReason};
pub use representation::{RepresentationMetadata, RepresentationTerm};
pub use semantic_id::SemanticId;
pub use uri::{MimQualifiedName, MimUri};
