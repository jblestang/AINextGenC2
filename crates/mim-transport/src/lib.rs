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
pub mod persistence;
pub mod rest;
pub mod secured;
pub mod wire;

pub use broker::ExchangeBroker;
pub use envelope::{
    envelope_from_json, envelope_to_json, unwrap_put_object, unwrap_put_object_with_format,
    wrap_put_object, wrap_put_object_with_format,
};
pub use error::{TransportError, TransportResult};
pub use filter::{parse_filter, FilterExpression, FilterPredicate};
pub use message::{
    DeleteObjectRequest, DeleteObjectResponse, ExchangeEnvelope, GetByFilterRequest,
    GetByFilterResponse, GetByOidRequest, GetByOidResponse, IesOperation, JournalEntry,
    PutObjectRequest, PutObjectResponse, SyncResponse,
};
pub use persistence::FileExchangeStore;
pub use rest::{paths, encode_oid_for_path, filter_from_query, HttpMethod, RestRoute};
pub use secured::SecuredExchangeBroker;
pub use wire::{
    detect_payload_format, format_from_content_type, negotiate_format, wire_registry,
    WirePayloadFormat, HEADER_MIM_VERSION, MEDIA_MIM_JSON, MEDIA_MIM_XML, MIM_VERSION,
};
