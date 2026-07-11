//! Compliance evaluation for STANAG 4774/4778, ZTDF, and DCS labeling.

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

pub mod checker;
pub mod report;
pub mod requirements;

pub use checker::LabelingComplianceChecker;
pub use report::{
    LabelingComplianceReport, LabelingComplianceStatus, LabelingDimension,
    LabelingDimensionResult,
};
pub use requirements::LabelingComplianceRequirements;
