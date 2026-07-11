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
pub mod envelope;
pub mod error;
pub mod filter;
pub mod message;
pub mod rest;
pub mod secured;

pub use broker::ExchangeBroker;
pub use envelope::{envelope_from_json, envelope_to_json, unwrap_put_object, wrap_put_object};
pub use error::{TransportError, TransportResult};
pub use filter::{parse_filter, FilterExpression, FilterPredicate};
pub use message::{
    DeleteObjectRequest, DeleteObjectResponse, ExchangeEnvelope, GetByFilterRequest,
    GetByFilterResponse, GetByOidRequest, GetByOidResponse, IesOperation, PutObjectRequest,
    PutObjectResponse,
};
pub use rest::{paths, encode_oid_for_path, filter_from_query, HttpMethod, RestRoute};
pub use secured::SecuredExchangeBroker;
