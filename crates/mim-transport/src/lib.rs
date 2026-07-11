//! MIP4-IES transport layer for MIM information exchange.
//!
//! Implements the MIP4 Information Exchange Specification service interface:
//! PutObject, GetByOID, GetByFilter, and DeleteObject over a REST binding.

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

pub mod broker;
pub mod error;
pub mod message;
pub mod rest;

pub use broker::ExchangeBroker;
pub use error::{TransportError, TransportResult};
pub use message::{
    DeleteObjectRequest, DeleteObjectResponse, ExchangeEnvelope, GetByFilterRequest,
    GetByFilterResponse, GetByOidRequest, GetByOidResponse, IesOperation, PutObjectRequest,
    PutObjectResponse,
};
pub use rest::{paths, HttpMethod, RestRoute};
