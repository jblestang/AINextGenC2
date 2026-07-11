use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;

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
