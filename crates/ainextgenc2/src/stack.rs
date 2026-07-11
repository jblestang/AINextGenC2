use std::fs::File;
use std::io::Read;
use std::path::Path;

use mim_compliance::{ComplianceChecker, ComplianceReport};
use mim_core::MimResult;
use mim_model::{MimManifest, ModelRegistry};
use mim_runtime::{ValidationReport, Validator};

/// Loaded MIM stack with model registry and compliance tooling.
#[derive(Clone, Debug)]
pub struct MimStack {
    manifest: MimManifest,
    registry: ModelRegistry,
}

impl MimStack {
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
        Self::load_embedded(&data)
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
    fn core_seed_is_not_yet_fully_compliant() {
        let stack = MimStack::load_core_seed().expect("stack");
        let report = stack.compliance_report();
        assert!(!report.is_fully_compliant);
    }
}
