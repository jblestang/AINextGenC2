//! Remote federation publisher abstraction for HTTP MIP4-IES replication.

use mim_runtime::{MimInstance, ObjectIdentifier};

use crate::error::TransportResult;
use crate::message::SyncResponse;

/// A coalition publisher reachable over MIP4-IES HTTP (sync + object fetch).
pub trait FederationPublisher {
    /// Fetch PEP-filtered replication journal entries since sequence `since`.
    fn fetch_sync(&self, since: u64) -> TransportResult<SyncResponse>;

    /// Fetch a single object by OID from the publisher (GetByOID).
    fn fetch_instance(&self, oid: &ObjectIdentifier) -> TransportResult<MimInstance>;
}
