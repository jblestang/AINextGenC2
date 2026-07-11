//! Import external model artifacts into MIM manifest JSON.

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

pub mod mapper;
pub mod owl;

pub use mapper::{ImportOptions, ImportReport, OwlImporter};
pub use owl::OwlModel;
