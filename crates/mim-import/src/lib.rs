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

pub mod fetch;
pub mod mapper;
pub mod owl;

pub use fetch::{download_to_path, load_owl_source, MIMWORLD_JC3IEDM_OWL_URL, MIMWORLD_MIM_OWL_URL};
pub use mapper::{ImportOptions, ImportReport, OwlImporter};
pub use owl::OwlModel;
