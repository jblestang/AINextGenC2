//! MIP4-IES conformance test suite runner for FMN accreditation path.

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

pub mod report;
pub mod runner;

pub use report::{Mip4ConformanceReport, Mip4SuiteResult, Mip4TestResult};
pub use runner::Mip4ConformanceRunner;
