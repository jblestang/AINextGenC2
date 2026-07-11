//! MIM runtime instances, validation, and serialization.

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

pub mod instance;
pub mod oid;
pub mod serialize;
pub mod validate;

pub use instance::{InstanceStore, MimInstance, PropertyValue};
pub use oid::ObjectIdentifier;
pub use serialize::{SerializationFormat, Serializer};
pub use validate::{ValidationIssue, ValidationReport, Validator};
