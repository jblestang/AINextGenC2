use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::log::AuditLog;

/// Write SIEM-oriented JSON export to a file path.
pub fn forward_siem_to_file(log: &AuditLog, path: impl AsRef<Path>) -> Result<(), String> {
    let json = log.export_siem()?;
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut file = fs::File::create(path).map_err(|e| e.to_string())?;
    file.write_all(json.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Retry an operation with exponential backoff (accredited SIEM forwarding).
pub fn forward_with_retry<F>(max_attempts: u32, mut operation: F) -> Result<(), String>
where
    F: FnMut() -> Result<(), String>,
{
    let attempts = max_attempts.max(1);
    let mut delay_ms = 100u64;
    let mut last_err = String::from("no attempts made");
    for attempt in 1..=attempts {
        match operation() {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = err;
                if attempt < attempts {
                    thread::sleep(Duration::from_millis(delay_ms));
                    delay_ms = delay_ms.saturating_mul(2);
                }
            }
        }
    }
    Err(format!(
        "accredited SIEM forward failed after {attempts} attempts: {last_err}"
    ))
}

/// POST SIEM JSON to an HTTP endpoint (`host:port/path` or full `http://` URL).
pub fn forward_siem_http(endpoint: &str, json: &str) -> Result<(), String> {
    let (host, port, path) = parse_http_endpoint(endpoint)?;
    let body_len = json.len();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n{json}"
    );
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write request: {e}"))?;
    Ok(())
}

/// Export and forward the audit log to an HTTP SIEM collector.
pub fn forward_log_http(log: &AuditLog, endpoint: &str) -> Result<(), String> {
    let json = log.export_siem()?;
    forward_siem_http(endpoint, &json)
}

/// Forward SIEM JSON to an HTTP endpoint with retry (accredited profile).
pub fn forward_log_http_accredited(log: &AuditLog, endpoint: &str, max_attempts: u32) -> Result<(), String> {
    let json = log.export_siem()?;
    let endpoint = endpoint.to_owned();
    forward_with_retry(max_attempts, || forward_siem_http(&endpoint, &json))
}

/// Emit an RFC 5424 syslog message over TCP (`host:port`).
pub fn forward_syslog_tcp(
    endpoint: &str,
    facility: u8,
    severity: u8,
    message: &str,
) -> Result<(), String> {
    let (host, port) = parse_syslog_endpoint(endpoint)?;
    let priority = (facility as u16) * 8 + severity as u16;
    let payload = format!("<{priority}>1 - - - - - - {message}\n");
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| format!("write syslog: {e}"))?;
    Ok(())
}

/// Export audit log as SIEM JSON and forward via syslog TCP with retry.
pub fn forward_log_syslog_accredited(
    log: &AuditLog,
    endpoint: &str,
    max_attempts: u32,
) -> Result<(), String> {
    let json = log.export_siem()?;
    let endpoint = endpoint.to_owned();
    forward_with_retry(max_attempts, || {
        forward_syslog_tcp(&endpoint, 20, 6, &json)
    })
}

fn parse_http_endpoint(endpoint: &str) -> Result<(String, u16, String), String> {
    let trimmed = endpoint.trim();
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let (authority, path) = match without_scheme.split_once('/') {
        Some((auth, rest)) => (auth, format!("/{rest}")),
        None => (without_scheme, "/".to_owned()),
    };
    let (host, port) = match authority.split_once(':') {
        Some((host, port_str)) => {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port in endpoint '{endpoint}'"))?;
            (host.to_owned(), port)
        }
        None => (authority.to_owned(), 80),
    };
    if host.is_empty() {
        return Err(format!("invalid HTTP endpoint '{endpoint}'"));
    }
    Ok((host, port, path))
}

fn parse_syslog_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    let trimmed = endpoint.trim();
    let without_scheme = trimmed
        .strip_prefix("tcp://")
        .or_else(|| trimmed.strip_prefix("syslog://"))
        .unwrap_or(trimmed);
    let (host, port) = match without_scheme.split_once(':') {
        Some((host, port_str)) => {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port in syslog endpoint '{endpoint}'"))?;
            (host.to_owned(), port)
        }
        None => (without_scheme.to_owned(), 514),
    };
    if host.is_empty() {
        return Err(format!("invalid syslog endpoint '{endpoint}'"));
    }
    Ok((host, port))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};

    use super::*;
    use crate::record::{AuditEventKind, AuditRecord};

    #[test]
    fn parses_http_endpoint() {
        let (host, port, path) =
            parse_http_endpoint("http://siem.example.com:8080/api/events").expect("parse");
        assert_eq!(host, "siem.example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/api/events");
    }

    #[test]
    fn parses_syslog_endpoint() {
        let (host, port) =
            parse_syslog_endpoint("tcp://siem.example.com:1514").expect("parse");
        assert_eq!(host, "siem.example.com");
        assert_eq!(port, 1514);
    }

    #[test]
    fn retry_invokes_operation() {
        let mut calls = 0u32;
        let result = forward_with_retry(3, || {
            calls += 1;
            if calls < 2 {
                Err("transient".into())
            } else {
                Ok(())
            }
        });
        assert!(result.is_ok());
        assert_eq!(calls, 2);
    }

    #[test]
    fn writes_siem_export_file() {
        let log = AuditLog::memory();
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        log.record(AuditRecord::new(
            AuditEventKind::CrossDomainEvaluate,
            "guard",
            label,
            "rule",
            "allow",
            "test",
        ))
        .expect("record");
        let path = std::env::temp_dir().join("mim-audit-siem-test.json");
        forward_siem_to_file(&log, &path).expect("export");
        let contents = fs::read_to_string(&path).expect("read");
        assert!(contents.contains("AINextGenC2"));
        let _ = fs::remove_file(path);
    }
}
