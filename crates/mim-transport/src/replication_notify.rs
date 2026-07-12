//! Coalition replication webhook notification (notify + pull pattern).

use std::thread;
use std::time::Duration;

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

/// Retry and timeout policy for coalition replication webhooks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicationNotifyOptions {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub timeout_secs: u64,
}

impl Default for ReplicationNotifyOptions {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 100,
            timeout_secs: 5,
        }
    }
}

/// Per-target webhook delivery outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookNotifyResult {
    pub url: String,
    pub delivered: bool,
    pub attempts: u32,
    pub error: Option<String>,
}

/// Aggregate report for a notify round.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReplicationNotifyReport {
    pub results: Vec<WebhookNotifyResult>,
}

impl ReplicationNotifyReport {
    pub fn all_delivered(&self) -> bool {
        self.results.iter().all(|result| result.delivered)
    }

    pub fn delivered_count(&self) -> usize {
        self.results.iter().filter(|result| result.delivered).count()
    }
}

/// POST replication notify to coalition subscriber webhooks with retry and reporting.
pub fn notify_webhooks_with_options(
    urls: &[String],
    latest_sequence: u64,
    options: &ReplicationNotifyOptions,
) -> ReplicationNotifyReport {
    if urls.is_empty() {
        return ReplicationNotifyReport::default();
    }
    let body = ReplicationNotifyPayload::new(latest_sequence);
    let mut results = Vec::with_capacity(urls.len());
    for url in urls {
        results.push(notify_target_with_retry(url, &body, options));
    }
    ReplicationNotifyReport { results }
}

/// Default coalition notify: synchronous delivery with retry (no fire-and-forget thread).
pub fn notify_webhooks(urls: &[String], latest_sequence: u64) -> ReplicationNotifyReport {
    notify_webhooks_with_options(urls, latest_sequence, &ReplicationNotifyOptions::default())
}

fn notify_target_with_retry(
    url: &str,
    body: &ReplicationNotifyPayload,
    options: &ReplicationNotifyOptions,
) -> WebhookNotifyResult {
    let max_attempts = options.max_attempts.max(1);
    let mut delay_ms = options.initial_backoff_ms.max(1);
    let mut last_err = None;
    for attempt in 1..=max_attempts {
        match post_notify(url, body, options.timeout_secs) {
            Ok(()) => {
                return WebhookNotifyResult {
                    url: url.to_owned(),
                    delivered: true,
                    attempts: attempt,
                    error: None,
                };
            }
            Err(err) => {
                last_err = Some(err.to_string());
                if attempt < max_attempts {
                    thread::sleep(Duration::from_millis(delay_ms));
                    delay_ms = delay_ms.saturating_mul(2);
                }
            }
        }
    }
    WebhookNotifyResult {
        url: url.to_owned(),
        delivered: false,
        attempts: max_attempts,
        error: last_err,
    }
}

fn post_notify(
    url: &str,
    body: &ReplicationNotifyPayload,
    timeout_secs: u64,
) -> TransportResult<()> {
    let response = ureq::post(url)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(timeout_secs.max(1)))
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    #[test]
    fn serializes_notify_payload() {
        let json = serde_json::to_string(&ReplicationNotifyPayload::new(42)).expect("json");
        assert!(json.contains("latestSequence"));
    }

    fn spawn_ok_server() -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                read_http_request(&mut stream);
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{addr}/notify"), handle)
    }

    fn read_http_request(stream: &mut TcpStream) {
        let mut buffer = [0u8; 4096];
        let _ = stream.read(&mut buffer);
    }

    #[test]
    fn notify_delivers_on_success() {
        let (url, handle) = spawn_ok_server();
        let report = notify_webhooks_with_options(
            &[url],
            7,
            &ReplicationNotifyOptions {
                max_attempts: 3,
                initial_backoff_ms: 1,
                timeout_secs: 2,
            },
        );
        handle.join().expect("server");
        assert!(report.all_delivered());
        assert_eq!(report.results[0].attempts, 1);
    }

    #[test]
    fn notify_retries_then_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept");
                read_http_request(&mut stream);
                let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                let status = if count == 0 { "500" } else { "200" };
                let response = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Length: 2\r\n\r\n{{}}"
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        let url = format!("http://{addr}/notify");
        let report = notify_webhooks_with_options(
            &[url],
            9,
            &ReplicationNotifyOptions {
                max_attempts: 3,
                initial_backoff_ms: 1,
                timeout_secs: 2,
            },
        );
        handle.join().expect("server");
        assert!(report.all_delivered());
        assert_eq!(report.results[0].attempts, 2);
    }

    #[test]
    fn notify_reports_failure_after_exhausted_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept");
                read_http_request(&mut stream);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
            }
        });
        let url = format!("http://{addr}/notify");
        let report = notify_webhooks_with_options(
            &[url],
            1,
            &ReplicationNotifyOptions {
                max_attempts: 2,
                initial_backoff_ms: 1,
                timeout_secs: 2,
            },
        );
        handle.join().expect("server");
        assert!(!report.all_delivered());
        assert_eq!(report.results[0].attempts, 2);
        assert!(report.results[0].error.as_ref().is_some_and(|e| e.contains("503")));
    }
}
