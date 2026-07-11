//! MIM compliance checking and reporting framework.

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

pub use checker::ComplianceChecker;
pub use report::{ComplianceDimension, ComplianceReport, ComplianceStatus};
pub use requirements::ComplianceRequirements;
