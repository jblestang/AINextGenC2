//! MIM taxonomy, metadata, code lists, and model registry.

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

pub mod codelist;
pub mod manifest;
pub mod metadata;
pub mod registry;
pub mod taxonomy;

pub use codelist::{CodeList, CodeListKind, CodeValue};
pub use manifest::{MimManifest, ModelElementKind, ModelElementSpec};
pub use metadata::{
    Metadata, Observer, OperationalAppraisal, Reporter, SecurityClassification, ValidityPeriod,
};
pub use registry::ModelRegistry;
pub use taxonomy::{ActionKind, ObjectKind, TaxonomyNode};
