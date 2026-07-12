//! HTTP client for coalition MIP4-IES federation (remote sync + object fetch).

use mim_runtime::{MimInstance, ObjectIdentifier};
use mim_transport::{
    encode_oid_for_path, FederationPublisher, GetByOidResponse, ReplicationApplyReport,
    SyncResponse, TransportError, TransportResult,
};
use mim_transport::FederationConfig;
use reqwest::header::{HeaderMap, HeaderValue};

use crate::identity::{HEADER_MIM_CLIENT_CN, HEADER_MIM_CLIENT_PRINCIPAL};

/// Coalition peer client for PEP-filtered replication over HTTPS.
#[derive(Clone, Debug)]
pub struct HttpFederationClient {
    client: reqwest::Client,
    sync_url: String,
    objects_base_url: String,
    identity_headers: HeaderMap,
}

impl HttpFederationClient {
    /// Connect to a publisher sync endpoint (e.g. `https://usa-c2.fmn.mil/mip4-ies/v1/sync`).
    pub fn new(sync_url: impl Into<String>) -> TransportResult<Self> {
        let sync_url = sync_url.into();
        let objects_base_url = derive_objects_base_url(&sync_url)?;
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| TransportError::Validation(format!("HTTP client: {e}")))?;
        Ok(Self {
            client,
            sync_url,
            objects_base_url,
            identity_headers: HeaderMap::new(),
        })
    }

    pub fn with_client_cn(mut self, cn: impl Into<String>) -> TransportResult<Self> {
        let value = HeaderValue::from_str(&cn.into())
            .map_err(|e| TransportError::InvalidRequest(format!("client CN header: {e}")))?;
        self.identity_headers.insert(HEADER_MIM_CLIENT_CN, value);
        Ok(self)
    }

    pub fn with_client_principal(mut self, principal: impl Into<String>) -> TransportResult<Self> {
        let value = HeaderValue::from_str(&principal.into()).map_err(|e| {
            TransportError::InvalidRequest(format!("client principal header: {e}"))
        })?;
        self.identity_headers
            .insert(HEADER_MIM_CLIENT_PRINCIPAL, value);
        Ok(self)
    }

    pub fn sync_url(&self) -> &str {
        &self.sync_url
    }

    /// Build a client for a coalition peer URL from [`FederationConfig`].
    pub fn from_federation_config(
        config: &FederationConfig,
        peer_sync_url: &str,
        client_cn: impl Into<String>,
    ) -> TransportResult<Self> {
        let _ = config;
        Self::new(peer_sync_url)?.with_client_cn(client_cn)
    }

    /// Pull PEP-filtered journal entries and replicate objects into a local broker.
    pub async fn replicate_into(
        &self,
        consumer: &mut mim_transport::ExchangeBroker,
        since: u64,
    ) -> TransportResult<ReplicationApplyReport> {
        let sync = self.fetch_sync_async(since).await?;
        let mut applied = 0;
        let mut skipped = 0;

        for entry in sync.entries {
            if consumer.last_applied_sequence() >= entry.sequence {
                skipped += 1;
                continue;
            }
            let instance = if entry.operation == mim_transport::IesOperation::PutObject {
                Some(self.fetch_instance_async(&entry.oid).await?)
            } else {
                None
            };
            consumer.apply_remote_entry(&entry, instance)?;
            applied += 1;
        }

        Ok(ReplicationApplyReport {
            applied,
            skipped,
            latest_sequence: sync.latest_sequence,
        })
    }

    async fn fetch_sync_async(&self, since: u64) -> TransportResult<SyncResponse> {
        let url = if since == 0 {
            self.sync_url.clone()
        } else {
            format!("{}?since={since}", self.sync_url)
        };
        let response = self
            .client
            .get(&url)
            .headers(self.identity_headers.clone())
            .send()
            .await
            .map_err(|e| TransportError::Validation(format!("sync GET failed: {e}")))?;
        if !response.status().is_success() {
            return Err(TransportError::Validation(format!(
                "sync GET {} returned {}",
                url,
                response.status()
            )));
        }
        response
            .json::<SyncResponse>()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))
    }

    async fn fetch_instance_async(&self, oid: &ObjectIdentifier) -> TransportResult<MimInstance> {
        let encoded = encode_oid_for_path(oid.as_str());
        let url = format!("{}/{}", self.objects_base_url, encoded);
        let response = self
            .client
            .get(&url)
            .headers(self.identity_headers.clone())
            .send()
            .await
            .map_err(|e| TransportError::Validation(format!("object GET failed: {e}")))?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            return Err(map_http_status(status, &url));
        }
        let body: GetByOidResponse = response
            .json()
            .await
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        Ok(body.instance)
    }
}

impl FederationPublisher for HttpFederationClient {
    fn fetch_sync(&self, since: u64) -> TransportResult<SyncResponse> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| {
                TransportError::Validation(
                    "async runtime required for HTTP federation; use replicate_into().await"
                        .into(),
                )
            })?
            .block_on(self.fetch_sync_async(since))
    }

    fn fetch_instance(&self, oid: &ObjectIdentifier) -> TransportResult<MimInstance> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| {
                TransportError::Validation(
                    "async runtime required for HTTP federation; use replicate_into().await"
                        .into(),
                )
            })?
            .block_on(self.fetch_instance_async(oid))
    }
}

fn derive_objects_base_url(sync_url: &str) -> TransportResult<String> {
    let trimmed = sync_url.trim_end_matches('/');
    let api_base = trimmed
        .strip_suffix("/sync")
        .ok_or_else(|| {
            TransportError::InvalidRequest(format!(
                "federation sync URL must end with /sync: {sync_url}"
            ))
        })?;
    Ok(format!("{api_base}/objects"))
}

fn map_http_status(status: u16, url: &str) -> TransportError {
    match status {
        404 => TransportError::NotFound(url.to_owned()),
        410 => TransportError::Inactive(url.to_owned()),
        403 => TransportError::Forbidden(format!("PEP denied GET {url}")),
        _ => TransportError::Validation(format!("GET {url} returned HTTP {status}")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn derives_objects_base_from_sync_url() {
        let base = derive_objects_base_url("https://usa-c2.fmn.mil/mip4-ies/v1/sync").expect("base");
        assert_eq!(base, "https://usa-c2.fmn.mil/mip4-ies/v1/objects");
    }
}
