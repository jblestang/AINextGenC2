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
pub mod instance_schema;
pub mod oid;
pub mod serialize;
pub mod validate;
pub mod xsd;

pub use instance::{InstanceStore, MimInstance, PropertyValue};
pub use instance_schema::validate_serialized_instance;
pub use oid::ObjectIdentifier;
pub use serialize::{SerializationFormat, Serializer, MIM_JSONLD_CONTEXT};
pub use validate::{ValidationIssue, ValidationReport, Validator};
pub use xsd::validate_exchange_xsd;
