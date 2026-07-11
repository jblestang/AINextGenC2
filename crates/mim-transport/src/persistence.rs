use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use mim_model::ModelRegistry;
use mim_runtime::{MimInstance, ObjectIdentifier};
use serde::{Deserialize, Serialize};

use crate::broker::ExchangeBroker;
use crate::error::{TransportError, TransportResult};
use crate::message::JournalEntry;

/// On-disk snapshot of an exchange broker (instances, inactive set, replication journal).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeSnapshot {
    model_version: String,
    instances: Vec<MimInstance>,
    inactive: Vec<ObjectIdentifier>,
    journal: Vec<JournalEntry>,
    sequence: u64,
}

/// File-backed persistence for MIP4-IES exchange state.
#[derive(Clone, Debug)]
pub struct FileExchangeStore {
    path: PathBuf,
}

impl FileExchangeStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self, registry: ModelRegistry) -> TransportResult<ExchangeBroker> {
        if !self.path.exists() {
            return Ok(ExchangeBroker::new(registry));
        }

        let file = File::open(&self.path).map_err(|e| TransportError::Serialization(e.to_string()))?;
        let reader = BufReader::new(file);
        let snapshot: ExchangeSnapshot = serde_json::from_reader(reader)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;

        if snapshot.model_version != registry.version() {
            return Err(TransportError::Validation(format!(
                "snapshot model version {} does not match registry {}",
                snapshot.model_version,
                registry.version()
            )));
        }

        Ok(ExchangeBroker::from_snapshot(
            registry,
            snapshot.instances,
            snapshot.inactive,
            snapshot.journal,
            snapshot.sequence,
        ))
    }

    pub fn save(&self, broker: &ExchangeBroker) -> TransportResult<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| TransportError::Serialization(e.to_string()))?;
        }

        let snapshot = ExchangeSnapshot {
            model_version: broker.registry().version().to_owned(),
            instances: broker.instances().cloned().collect(),
            inactive: broker.inactive_oids().cloned().collect(),
            journal: broker.journal().to_vec(),
            sequence: broker.latest_sequence(),
        };

        let json = serde_json::to_string_pretty(&snapshot)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        let mut file = File::create(&self.path)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        file.write_all(json.as_bytes())
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        Ok(())
    }

    /// Append-only JSONL journal for replication audit (optional secondary file).
    pub fn append_journal_entry(&self, entry: &JournalEntry) -> TransportResult<()> {
        let journal_path = self.path.with_extension("journal.jsonl");
        if let Some(parent) = journal_path.parent() {
            fs::create_dir_all(parent).map_err(|e| TransportError::Serialization(e.to_string()))?;
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_path)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        let line = serde_json::to_string(entry)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        writeln!(file, "{line}").map_err(|e| TransportError::Serialization(e.to_string()))?;
        Ok(())
    }

    pub fn read_journal_since(&self, since: u64) -> TransportResult<Vec<JournalEntry>> {
        let journal_path = self.path.with_extension("journal.jsonl");
        if !journal_path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(journal_path).map_err(|e| TransportError::Serialization(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|e| TransportError::Serialization(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: JournalEntry = serde_json::from_str(&line)
                .map_err(|e| TransportError::Serialization(e.to_string()))?;
            if entry.sequence > since {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::SemanticId;
    use mim_runtime::PropertyValue;

    use super::*;
    use crate::message::PutObjectRequest;

    fn test_registry() -> ModelRegistry {
        use mim_core::MimUri;
        use mim_model::manifest::{ModelElementKind, ModelElementSpec};
        use mim_model::TaxonomyNode;

        ModelRegistry::from_manifest(mim_model::MimManifest {
            version: "5.1.0".into(),
            release_date: "2020-09-28".into(),
            description: "minimal".into(),
            expected_object_types: 1,
            expected_action_types: 0,
            expected_code_lists: 0,
            taxonomy: vec![TaxonomyNode {
                name: "Target".into(),
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
                parent: None,
                object_kind: Some(mim_model::ObjectKind::InformationResource),
                action_kind: None,
                definition: "Target".into(),
                package_path: "Classifiers::Object::InformationResource::Target".into(),
            }],
            elements: vec![ModelElementSpec {
                name: "Target".into(),
                kind: ModelElementKind::Class,
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
                uri: MimUri::parse(
                    "https://www.mimworld.org/mim/5.1.0/Classifiers/Object/InformationResource/Target",
                )
                .expect("uri"),
                package_path: "Classifiers::Object::InformationResource::Target".into(),
                definition: "Target".into(),
                parent_class: None,
                representation_term: None,
                representation_metadata: None,
                multiplicity_lower: None,
                multiplicity_upper: None,
                is_mandatory: false,
                is_nillable: true,
            }],
            code_lists: vec![],
        })
        .expect("registry")
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("mim-store-{:?}", std::time::SystemTime::now()));
        let store_path = dir.join("exchange.json");
        let file_store = FileExchangeStore::new(store_path);

        let mut broker = ExchangeBroker::new(test_registry());
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        broker
            .put_object(PutObjectRequest {
                instance: mim_runtime::MimInstance::new("Target", class_id)
                    .expect("instance")
                    .with_property(PropertyValue::string("nameText", "HOSTILE-1")),
            })
            .expect("put");

        file_store.save(&broker).expect("save");
        let restored = file_store.load(test_registry()).expect("load");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.latest_sequence(), 1);
    }
}
