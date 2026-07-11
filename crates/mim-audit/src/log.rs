use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use mim_crypto::SigningKey;
use thiserror::Error;

use crate::chain::AuditEnvelope;
use crate::record::AuditRecord;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit I/O error: {0}")]
    Io(String),
    #[error("audit record is sealed and cannot be modified")]
    Sealed,
}

pub type AuditResult<T> = Result<T, AuditError>;

/// Append-only audit log — records cannot be updated or deleted once written.
pub trait AuditSink: Send + Sync {
    fn append_record(&self, record: &AuditRecord) -> AuditResult<()> {
        let _ = record;
        Ok(())
    }

    fn append_envelope(&self, envelope: &AuditEnvelope) -> AuditResult<()> {
        let _ = envelope;
        Ok(())
    }

    fn len(&self) -> usize;
}

/// In-memory audit sink for tests and embedded deployments.
#[derive(Clone, Debug, Default)]
pub struct MemoryAuditSink {
    records: Arc<Mutex<Vec<AuditRecord>>>,
}

impl MemoryAuditSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        self.records
            .lock()
            .map(|records| records.clone())
            .unwrap_or_default()
    }
}

impl AuditSink for MemoryAuditSink {
    fn append_record(&self, record: &AuditRecord) -> AuditResult<()> {
        let mut guard = self
            .records
            .lock()
            .map_err(|_| AuditError::Sealed)?;
        guard.push(record.clone());
        Ok(())
    }

    fn len(&self) -> usize {
        self.records.lock().map(|r| r.len()).unwrap_or(0)
    }
}

/// File-backed append-only audit log (tamper-evident envelope JSON lines).
#[derive(Clone, Debug)]
pub struct FileAuditSink {
    path: std::path::PathBuf,
    count: Arc<Mutex<usize>>,
}

impl FileAuditSink {
    pub fn open(path: impl AsRef<Path>) -> AuditResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| AuditError::Io(e.to_string()))?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(Self {
            path,
            count: Arc::new(Mutex::new(0)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileAuditSink {
    fn append_envelope(&self, envelope: &AuditEnvelope) -> AuditResult<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let mut writer = BufWriter::new(file);
        let line = envelope
            .to_json_line()
            .map_err(|e| AuditError::Io(e))?;
        writeln!(writer, "{line}").map_err(|e| AuditError::Io(e.to_string()))?;
        writer.flush().map_err(|e| AuditError::Io(e.to_string()))?;
        if let Ok(mut count) = self.count.lock() {
            *count += 1;
        }
        Ok(())
    }

    fn len(&self) -> usize {
        self.count.lock().map(|c| *c).unwrap_or(0)
    }
}

/// Facade over an audit sink with hash-chain and optional NMBS signing.
#[derive(Clone)]
pub struct AuditLog {
    sink: Arc<dyn AuditSink>,
    chain: Arc<Mutex<ChainState>>,
}

#[derive(Clone)]
struct ChainState {
    previous_hash: String,
    envelopes: Vec<AuditEnvelope>,
    signing_key: Option<SigningKey>,
    verifying_key: Option<mim_crypto::VerifyingKey>,
}

impl AuditLog {
    pub fn new(sink: impl AuditSink + 'static) -> Self {
        Self {
            sink: Arc::new(sink),
            chain: Arc::new(Mutex::new(ChainState {
                previous_hash: "GENESIS".to_owned(),
                envelopes: Vec::new(),
                signing_key: None,
                verifying_key: None,
            })),
        }
    }

    pub fn memory() -> Self {
        Self::new(MemoryAuditSink::new())
    }

    pub fn file(path: impl AsRef<Path>) -> AuditResult<Self> {
        Ok(Self::new(FileAuditSink::open(path)?))
    }

    /// Reload a hash-chained audit log from envelope JSON lines on disk.
    pub fn load_from_file(path: impl AsRef<Path>) -> AuditResult<Self> {
        let path = path.as_ref();
        let sink = FileAuditSink::open(path)?;
        let file = fs::File::open(path).map_err(|e| AuditError::Io(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut envelopes = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|e| AuditError::Io(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let envelope = AuditEnvelope::from_json_line(&line)
                .map_err(|e| AuditError::Io(e))?;
            envelopes.push(envelope);
        }
        let previous_hash = envelopes
            .last()
            .map(|env| env.record_hash.clone())
            .unwrap_or_else(|| "GENESIS".to_owned());
        Ok(Self {
            sink: Arc::new(sink),
            chain: Arc::new(Mutex::new(ChainState {
                previous_hash,
                envelopes,
                signing_key: None,
                verifying_key: None,
            })),
        })
    }

    /// Enable NMBS-signed, hash-chained audit envelopes on every record.
    pub fn with_signing_key(self, signing_key: SigningKey) -> Self {
        if let Ok(mut chain) = self.chain.lock() {
            chain.signing_key = Some(signing_key.clone());
            if let Ok(public_der) = mim_crypto::selected_provider()
                .public_key_from_private(signing_key.der())
            {
                if let Ok(verifying) =
                    mim_crypto::VerifyingKey::from_spki_der(signing_key.key_id.clone(), &public_der)
                {
                    chain.verifying_key = Some(verifying);
                }
            }
        }
        self
    }

    pub fn record(&self, record: AuditRecord) -> AuditResult<()> {
        self.sink.append_record(&record)?;
        if let Ok(mut chain) = self.chain.lock() {
            let mut envelope = AuditEnvelope::seal(record, &chain.previous_hash);
            if let Some(key) = &chain.signing_key {
                envelope = envelope.sign(key).map_err(|e| AuditError::Io(e))?;
            }
            self.sink.append_envelope(&envelope)?;
            chain.previous_hash = envelope.record_hash.clone();
            chain.envelopes.push(envelope);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.chain
            .lock()
            .map(|chain| chain.envelopes.len())
            .unwrap_or(0)
    }

    pub fn envelopes(&self) -> Vec<AuditEnvelope> {
        self.chain
            .lock()
            .map(|chain| chain.envelopes.clone())
            .unwrap_or_default()
    }

    pub fn export_siem(&self) -> Result<String, String> {
        crate::chain::export_siem_json(&self.envelopes())
    }

    pub fn verify_chain(&self) -> Result<(), String> {
        let chain = self.chain.lock().map_err(|_| "audit chain sealed".to_string())?;
        let mut previous = "GENESIS".to_string();
        for envelope in &chain.envelopes {
            envelope.verify_chain(&previous)?;
            if let Some(verifying) = &chain.verifying_key {
                envelope.verify_signature(verifying)?;
            }
            previous = envelope.record_hash.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{ClassificationLevel, ConfidentialityLabel, LabelPolicy};

    use super::*;
    use crate::record::AuditEventKind;

    #[test]
    fn append_only_memory_log() {
        let sink = MemoryAuditSink::new();
        let log = AuditLog::new(sink.clone());
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        log.record(AuditRecord::new(
            AuditEventKind::CrossDomainEvaluate,
            "guard",
            label,
            "rule-1",
            "downgrade",
            "secret to restricted",
        ))
        .expect("append");
        assert_eq!(sink.records().len(), 1);
    }

    #[test]
    fn file_sink_persists_envelopes_and_reloads() {
        let path = std::env::temp_dir().join(format!(
            "mim-audit-envelope-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let log = AuditLog::file(&path).expect("open");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        log.record(AuditRecord::new(
            AuditEventKind::CrossDomainTransfer,
            "guard",
            label,
            "rule",
            "allow",
            "released",
        ))
        .expect("record");
        assert_eq!(log.len(), 1);
        let reloaded = AuditLog::load_from_file(&path).expect("reload");
        assert_eq!(reloaded.len(), 1);
        reloaded.verify_chain().expect("chain");
        let _ = fs::remove_file(path);
    }
}
