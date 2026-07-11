//! STANAG 4778 metadata binding mechanism (ADatP-4778).
//!
//! Binds STANAG 4774 confidentiality labels to MIM data objects using
//! embedded, encapsulated, detached, and assertion binding profiles.

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
pub mod binding;
pub mod bdo;

pub use assertion::{AssertionBinding, BindingSignature};
pub use binding::{BindingMethod, BindingProfile, MetadataBinding};
pub use bdo::BindingDataObject;
