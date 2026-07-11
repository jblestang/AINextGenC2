//! Data-Centric Security (DCS) cross-domain solution for MIM exchanges.
//!
//! Evaluates STANAG 4774 labels against domain policies and orchestrates
//! labeled transfers between security domains with downgrade support.

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

pub mod guard;
pub mod labeled_exchange;
pub mod transfer;

pub use guard::{CrossDomainGuard, GuardDecision, GuardResult};
pub use labeled_exchange::LabeledMimExchange;
pub use transfer::{CrossDomainTransfer, TransferOutcome};
