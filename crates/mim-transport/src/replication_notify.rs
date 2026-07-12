//! Coalition replication webhook notification (notify + pull pattern).

use serde::{Deserialize, Serialize};

use crate::error::{TransportError, TransportResult};

/// Publisher → consumer journal notification payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationNotifyPayload {
    pub latest_sequence: u64,
    #[serde(default)]
    pub publisher_id: Option<String>,
}

impl ReplicationNotifyPayload {
    pub fn new(latest_sequence: u64) -> Self {
        Self {
            latest_sequence,
            publisher_id: None,
        }
    }
}

/// Best-effort POST of a replication notify to coalition subscriber webhooks.
pub fn notify_webhooks(urls: &[String], latest_sequence: u64) {
    if urls.is_empty() {
        return;
    }
    for url in urls {
        let url = url.clone();
        let body = ReplicationNotifyPayload::new(latest_sequence);
        std::thread::spawn(move || {
            let _ = post_notify(&url, &body);
        });
    }
}

fn post_notify(url: &str, body: &ReplicationNotifyPayload) -> TransportResult<()> {
    let response = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| TransportError::Validation(format!("webhook POST {url}: {e}")))?;
    if response.status() >= 400 {
        return Err(TransportError::Validation(format!(
            "webhook POST {url} returned HTTP {}",
            response.status()
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn serializes_notify_payload() {
        let json = serde_json::to_string(&ReplicationNotifyPayload::new(42)).expect("json");
        assert!(json.contains("latestSequence"));
    }
}
