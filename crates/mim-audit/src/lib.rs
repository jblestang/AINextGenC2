//! Immutable audit trail for DCS guard and policy enforcement decisions.

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

mod chain;
mod log;
mod record;
mod siem;
mod worm;

pub use chain::{export_siem_json, AuditEnvelope, AuditSignature};
pub use log::{AuditError, AuditLog, AuditResult, AuditSink, FileAuditSink, MemoryAuditSink};
pub use worm::WormAuditSink;
pub use record::{AuditEventKind, AuditRecord};
pub use siem::{
    forward_log_http, forward_log_http_accredited, forward_log_syslog_accredited,
    forward_siem_http, forward_siem_to_file, forward_syslog_tcp, forward_with_retry,
};
