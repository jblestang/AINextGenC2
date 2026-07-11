use std::fs::File;
use std::io::Read;
use std::path::Path;

use mim_compliance::{ComplianceChecker, ComplianceReport};
use mim_core::MimResult;
use mim_labeling_compliance::{LabelingComplianceChecker, LabelingComplianceReport};
use mim_model::{MimManifest, ModelRegistry};
use mim_runtime::{ValidationReport, Validator};

/// Loaded MIM stack with model registry and compliance tooling.
#[derive(Clone, Debug)]
pub struct MimStack {
    manifest: MimManifest,
    registry: ModelRegistry,
}

impl MimStack {
    /// Load the best available manifest: full import if present, else core seed.
    pub fn load() -> MimResult<Self> {
        let full_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../models/mim-full-5.1.json");
        if std::path::Path::new(full_path).exists() {
            return Self::load_path(full_path);
        }
        Self::load_core_seed()
    }

    /// Load the bundled core seed manifest.
    pub fn load_core_seed() -> MimResult<Self> {
        Self::load_embedded(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../models/mim-core-5.1.json"
        )))
    }

    /// Load a MIM manifest from JSON string.
    pub fn load_embedded(json: &str) -> MimResult<Self> {
        let manifest = MimManifest::from_json(json)?;
        let registry = ModelRegistry::from_manifest(manifest.clone())?;
        Ok(Self { manifest, registry })
    }

    /// Load a MIM manifest from filesystem path.
    pub fn load_path(path: impl AsRef<Path>) -> MimResult<Self> {
        let path = path.as_ref();
        let mut file = File::open(path)?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        let mut manifest = MimManifest::from_json(&data)?;
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains("mim-full"))
        {
            Self::merge_metadata_from_core(&mut manifest)?;
        }
        let registry = ModelRegistry::from_manifest(manifest.clone())?;
        Ok(Self { manifest, registry })
    }

    fn merge_metadata_from_core(full: &mut MimManifest) -> MimResult<()> {
        let core = MimManifest::from_json(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../models/mim-core-5.1.json"
        )))?;
        let metadata_names = [
            "Metadata",
            "Reporter",
            "Observer",
            "OperationalAppraisal",
            "ValidityPeriod",
            "SecurityClassification",
        ];
        for name in metadata_names {
            if !full.taxonomy.iter().any(|n| n.name == name) {
                if let Some(node) = core.taxonomy.iter().find(|n| n.name == name) {
                    full.taxonomy.push(node.clone());
                }
            }
            if !full.elements.iter().any(|e| e.name == name) {
                if let Some(element) = core.elements.iter().find(|e| e.name == name) {
                    full.elements.push(element.clone());
                }
            }
        }
        Ok(())
    }

    pub fn manifest(&self) -> &MimManifest {
        &self.manifest
    }

    pub fn registry(&self) -> &ModelRegistry {
        &self.registry
    }

    pub fn smoke_test_validator(&self) -> ValidationReport {
        let validator = Validator::new(&self.registry);
        validator.validate_store(&mim_runtime::InstanceStore::default())
    }

    pub fn compliance_report(&self) -> ComplianceReport {
        let checker = ComplianceChecker::with_defaults();
        let validation = self.smoke_test_validator();
        checker.evaluate(&self.manifest, &self.registry, &validation)
    }

    pub fn labeling_compliance_report(&self) -> LabelingComplianceReport {
        let _ = &self.registry;
        LabelingComplianceChecker::with_defaults().evaluate()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn loads_core_seed_manifest() {
        let stack = MimStack::load_core_seed().expect("stack");
        assert_eq!(stack.registry().version(), "5.1.0");
        assert!(stack.registry().object_type_count() > 0);
    }

    #[test]
    fn loads_full_manifest_when_present() {
        let full_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../models/mim-full-5.1.json");
        if !std::path::Path::new(full_path).exists() {
            return;
        }
        let stack = MimStack::load_path(full_path).expect("full stack");
        let report = stack.compliance_report();
        assert!(report.is_fully_compliant);
    }

    #[test]
    fn load_prefers_full_manifest() {
        let stack = MimStack::load().expect("stack");
        assert!(stack.registry().object_type_count() >= 2300);
        assert!(stack.registry().action_type_count() >= 500);
        assert!(stack.registry().code_list_count() >= 400);
    }
}
