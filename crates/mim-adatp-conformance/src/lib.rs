//! NATO ADatP conformance test suite runner.
//!
//! Implements test vectors from:
//! - ADatP-4774 Annex B / Table 17 (via surevine/spiffing reference suite)
//! - ADatP-4774.1 ACME SPIF semantic validation (Figures 7/9)
//! - ADatP-4778 assertion binding (NMBS Set/Verify operations)
//! - ZTDF / OpenTDF manifest with STANAG 4774 assertions

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

pub mod acme;
pub mod report;
pub mod runner;
pub mod vectors;
pub mod ztdf;

pub use report::{AdatpConformanceReport, AdatpSuiteResult, AdatpTestResult};
pub use runner::AdatpConformanceRunner;
