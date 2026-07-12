use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::chain::AuditEnvelope;
use crate::log::{AuditError, AuditResult, AuditSink};

/// Sidecar manifest tracking authoritative WORM file state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WormManifest {
    byte_length: u64,
    envelope_count: usize,
    last_record_hash: String,
}

/// Write-once read-many audit sink — append-only with tamper detection via sidecar manifest.
#[derive(Clone, Debug)]
pub struct WormAuditSink {
    path: PathBuf,
    manifest_path: PathBuf,
    state: Arc<Mutex<WormManifest>>,
}

impl WormAuditSink {
    pub fn open(path: impl AsRef<Path>) -> AuditResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| AuditError::Io(e.to_string()))?;
        }
        let manifest_path = manifest_path_for(&path);
        let state = if manifest_path.is_file() {
            load_manifest(&manifest_path)?
        } else if path.is_file() {
            let byte_length = fs::metadata(&path)
                .map_err(|e| AuditError::Io(e.to_string()))?
                .len();
            let (envelope_count, last_hash) = scan_envelopes(&path)?;
            WormManifest {
                byte_length,
                envelope_count,
                last_record_hash: last_hash,
            }
        } else {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| AuditError::Io(e.to_string()))?;
            WormManifest {
                byte_length: 0,
                envelope_count: 0,
                last_record_hash: "GENESIS".to_owned(),
            }
        };
        verify_file_length(&path, state.byte_length)?;
        let sink = Self {
            path,
            manifest_path,
            state: Arc::new(Mutex::new(state)),
        };
        sink.persist_manifest()?;
        Ok(sink)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Verify on-disk byte length matches the WORM manifest (detect truncation or in-place edits).
    pub fn verify_immutable(&self) -> AuditResult<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuditError::Sealed)?;
        verify_file_length(&self.path, state.byte_length)
    }

    fn persist_manifest(&self) -> AuditResult<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuditError::Sealed)?;
        write_manifest(&self.manifest_path, &state)
    }
}

impl AuditSink for WormAuditSink {
    fn append_envelope(&self, envelope: &AuditEnvelope) -> AuditResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuditError::Sealed)?;

        verify_file_length(&self.path, state.byte_length)?;

        let file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let mut writer = BufWriter::new(file);
        let line = envelope
            .to_json_line()
            .map_err(|e| AuditError::Io(e))?;
        writeln!(writer, "{line}").map_err(|e| AuditError::Io(e.to_string()))?;
        writer.flush().map_err(|e| AuditError::Io(e.to_string()))?;

        let new_length = fs::metadata(&self.path)
            .map_err(|e| AuditError::Io(e.to_string()))?
            .len();
        if new_length <= state.byte_length {
            return Err(AuditError::Tampered(
                "WORM audit file did not grow after append".into(),
            ));
        }

        state.byte_length = new_length;
        state.envelope_count += 1;
        state.last_record_hash = envelope.record_hash.clone();
        write_manifest(&self.manifest_path, &state)?;
        Ok(())
    }

    fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.envelope_count)
            .unwrap_or(0)
    }
}

fn manifest_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("audit.jsonl");
    path.with_file_name(format!("{file_name}.worm"))
}

fn verify_file_length(path: &Path, expected: u64) -> AuditResult<()> {
    if !path.is_file() {
        if expected == 0 {
            return Ok(());
        }
        return Err(AuditError::Tampered(format!(
            "WORM audit file missing; expected {expected} bytes"
        )));
    }
    let actual = fs::metadata(path)
        .map_err(|e| AuditError::Io(e.to_string()))?
        .len();
    if actual != expected {
        return Err(AuditError::Tampered(format!(
            "WORM audit file length mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn scan_envelopes(path: &Path) -> AuditResult<(usize, String)> {
    let file = fs::File::open(path).map_err(|e| AuditError::Io(e.to_string()))?;
    let reader = BufReader::new(file);
    let mut count = 0usize;
    let mut last_hash = "GENESIS".to_owned();
    for line in reader.lines() {
        let line = line.map_err(|e| AuditError::Io(e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        let envelope = AuditEnvelope::from_json_line(&line)
            .map_err(|e| AuditError::Io(e))?;
        last_hash = envelope.record_hash;
        count += 1;
    }
    Ok((count, last_hash))
}

fn load_manifest(path: &Path) -> AuditResult<WormManifest> {
    let data = fs::read_to_string(path).map_err(|e| AuditError::Io(e.to_string()))?;
    serde_json::from_str(&data).map_err(|e| AuditError::Io(e.to_string()))
}

fn write_manifest(path: &Path, manifest: &WormManifest) -> AuditResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| AuditError::Io(e.to_string()))?;
    }
    let json = serde_json::to_string_pretty(manifest).map_err(|e| AuditError::Io(e.to_string()))?;
    let tmp = path.with_extension("worm.tmp");
    {
        let mut file = fs::File::create(&tmp).map_err(|e| AuditError::Io(e.to_string()))?;
        file.write_all(json.as_bytes())
            .map_err(|e| AuditError::Io(e.to_string()))?;
        file.sync_all().map_err(|e| AuditError::Io(e.to_string()))?;
    }
    fs::rename(&tmp, path).map_err(|e| AuditError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};

    use super::*;
    use crate::log::AuditLog;
    use crate::record::{AuditEventKind, AuditRecord};

    fn temp_worm_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "mim-worm-audit-{}.jsonl",
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn worm_sink_detects_truncation() {
        let path = temp_worm_path();
        let log = AuditLog::worm(&path).expect("open");
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

        let file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate");
        file.set_len(0).expect("truncate");
        drop(file);

        let err = WormAuditSink::open(&path).expect_err("tamper");
        assert!(matches!(err, AuditError::Tampered(_)));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(manifest_path_for(&path));
    }

    #[test]
    fn worm_sink_persists_and_reloads() {
        let path = temp_worm_path();
        let log = AuditLog::worm(&path).expect("open");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Restricted);
        log.record(AuditRecord::new(
            AuditEventKind::CrossDomainTransfer,
            "guard",
            label,
            "rule",
            "downgrade",
            "released",
        ))
        .expect("record");
        let sink = WormAuditSink::open(&path).expect("reopen");
        sink.verify_immutable().expect("immutable");
        assert_eq!(sink.len(), 1);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(manifest_path_for(&path));
    }
}
