use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use thiserror::Error;

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
    fn append(&self, record: &AuditRecord) -> AuditResult<()>;
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
    fn append(&self, record: &AuditRecord) -> AuditResult<()> {
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

/// File-backed append-only audit log (JSON lines).
#[derive(Clone, Debug)]
pub struct FileAuditSink {
    path: std::path::PathBuf,
    count: Arc<Mutex<usize>>,
}

impl FileAuditSink {
    pub fn open(path: impl AsRef<Path>) -> AuditResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuditError::Io(e.to_string()))?;
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
}

impl AuditSink for FileAuditSink {
    fn append(&self, record: &AuditRecord) -> AuditResult<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let mut writer = BufWriter::new(file);
        let line = serde_json::to_string(record).map_err(|e| AuditError::Io(e.to_string()))?;
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

/// Facade over an audit sink with convenience helpers.
#[derive(Clone)]
pub struct AuditLog {
    sink: Arc<dyn AuditSink>,
}

impl AuditLog {
    pub fn new(sink: impl AuditSink + 'static) -> Self {
        Self {
            sink: Arc::new(sink),
        }
    }

    pub fn memory() -> Self {
        Self::new(MemoryAuditSink::new())
    }

    pub fn record(&self, record: AuditRecord) -> AuditResult<()> {
        self.sink.append(&record)
    }

    pub fn len(&self) -> usize {
        self.sink.len()
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
}
