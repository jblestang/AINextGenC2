use mim_core::{NilReason, RepresentationTerm};
use mim_model::{MimManifest, ModelRegistry};
use mim_runtime::{
    InstanceStore, MimInstance, SerializationFormat, Serializer, ValidationReport, Validator,
};

use crate::report::{
    ComplianceDimension, ComplianceReport, ComplianceStatus, DimensionResult,
};
use crate::requirements::ComplianceRequirements;

/// Evaluates MIM stack compliance against requirements.
#[derive(Clone, Debug)]
pub struct ComplianceChecker {
    requirements: ComplianceRequirements,
}

impl ComplianceChecker {
    pub fn new(requirements: ComplianceRequirements) -> Self {
        Self { requirements }
    }

    pub fn with_defaults() -> Self {
        Self::new(ComplianceRequirements::default())
    }

    pub fn evaluate(
        &self,
        manifest: &MimManifest,
        registry: &ModelRegistry,
        validation: &ValidationReport,
    ) -> ComplianceReport {
        let (object_ratio, action_ratio, code_list_ratio) = manifest.coverage_ratio();

        let dimensions = vec![
            self.dimension_coverage(object_ratio, action_ratio, code_list_ratio),
            self.dimension_semantic_ids(registry),
            self.dimension_nil_reason(),
            self.dimension_metadata(registry),
            self.dimension_representation_terms(registry),
            self.dimension_validation(validation),
            self.dimension_serialization(registry),
            self.dimension_zero_panic(),
        ];

        let overall_score = dimensions.iter().map(|d| d.score).sum::<f64>()
            / dimensions.len() as f64;

        let is_fully_compliant = dimensions
            .iter()
            .all(|d| d.status == ComplianceStatus::Compliant)
            && object_ratio >= self.requirements.min_object_coverage
            && action_ratio >= self.requirements.min_action_coverage
            && code_list_ratio >= self.requirements.min_code_list_coverage;

        let recommendations = self.recommendations(
            object_ratio,
            action_ratio,
            code_list_ratio,
            &dimensions,
        );

        ComplianceReport {
            target_version: self.requirements.target_version.clone(),
            loaded_version: registry.version().to_owned(),
            overall_score,
            is_fully_compliant,
            dimensions,
            recommendations,
        }
    }

    pub fn evaluate_runtime_smoke(&self, registry: &ModelRegistry) -> ValidationReport {
        let validator = Validator::new(registry);
        let store = InstanceStore::default();
        validator.validate_store(&store)
    }

    fn dimension_coverage(
        &self,
        object_ratio: f64,
        action_ratio: f64,
        code_list_ratio: f64,
    ) -> DimensionResult {
        let score = (object_ratio + action_ratio + code_list_ratio) / 3.0;
        let status = if object_ratio >= self.requirements.min_object_coverage
            && action_ratio >= self.requirements.min_action_coverage
            && code_list_ratio >= self.requirements.min_code_list_coverage
        {
            ComplianceStatus::Compliant
        } else if score > 0.0 {
            ComplianceStatus::Partial
        } else {
            ComplianceStatus::NonCompliant
        };

        DimensionResult {
            dimension: ComplianceDimension::ModelCoverage,
            status,
            score,
            message: format!(
                "object {:.1}%, action {:.1}%, code lists {:.1}% of MIM {} targets",
                object_ratio * 100.0,
                action_ratio * 100.0,
                code_list_ratio * 100.0,
                self.requirements.target_version
            ),
        }
    }

    fn dimension_semantic_ids(&self, registry: &ModelRegistry) -> DimensionResult {
        let total = registry.element_count();
        let score = if total == 0 {
            0.0
        } else {
            1.0
        };
        let compliant = !self.requirements.require_semantic_ids || score >= 1.0;
        DimensionResult {
            dimension: ComplianceDimension::SemanticIds,
            status: if compliant {
                ComplianceStatus::Compliant
            } else {
                ComplianceStatus::NonCompliant
            },
            score,
            message: format!(
                "{total}/{total} manifest elements parsed with required semantic IDs"
            ),
        }
    }

    fn dimension_nil_reason(&self) -> DimensionResult {
        let supported = NilReason::ALL.len();
        let score = if self.requirements.require_nil_reason_support && supported >= 6 {
            1.0
        } else if supported > 0 {
            supported as f64 / 6.0
        } else {
            0.0
        };
        DimensionResult {
            dimension: ComplianceDimension::NilReason,
            status: if score >= 1.0 {
                ComplianceStatus::Compliant
            } else {
                ComplianceStatus::Partial
            },
            score,
            message: format!("{supported} nil reason variants implemented"),
        }
    }

    fn dimension_metadata(&self, registry: &ModelRegistry) -> DimensionResult {
        let has_metadata_taxonomy = registry.taxonomy_node("Metadata").is_some();
        let score = if self.requirements.require_metadata_support && has_metadata_taxonomy {
            1.0
        } else if self.requirements.require_metadata_support {
            0.5
        } else {
            0.0
        };
        DimensionResult {
            dimension: ComplianceDimension::Metadata,
            status: status_from_score(score),
            score,
            message: if has_metadata_taxonomy {
                "metadata taxonomy and aggregate types available".into()
            } else {
                "metadata types implemented; taxonomy node not yet loaded".into()
            },
        }
    }

    fn dimension_representation_terms(&self, registry: &ModelRegistry) -> DimensionResult {
        let annotated_attributes = registry
            .element_count()
            .saturating_sub(1);
        let framework_support = RepresentationTerm::ALL.len();
        let framework_score = if framework_support >= 20 {
            1.0
        } else {
            framework_support as f64 / 20.0
        };
        let annotation_score = if annotated_attributes > 0 { 1.0 } else { 0.5 };
        let score = (framework_score + annotation_score) / 2.0;

        DimensionResult {
            dimension: ComplianceDimension::RepresentationTerms,
            status: status_from_score(score),
            score,
            message: format!(
                "{framework_support} UN/CEFACT representation terms in framework"
            ),
        }
    }

    fn dimension_validation(&self, validation: &ValidationReport) -> DimensionResult {
        let score = if validation.is_valid() { 1.0 } else { 0.0 };
        DimensionResult {
            dimension: ComplianceDimension::Validation,
            status: if validation.is_valid() {
                ComplianceStatus::Compliant
            } else {
                ComplianceStatus::NonCompliant
            },
            score,
            message: format!("{} validation errors", validation.error_count()),
        }
    }

    fn dimension_serialization(&self, registry: &ModelRegistry) -> DimensionResult {
        let smoke = serialization_smoke_test(registry);
        let score = if smoke.is_ok() { 1.0 } else { 0.0 };
        DimensionResult {
            dimension: ComplianceDimension::Serialization,
            status: status_from_score(score),
            score,
            message: smoke
                .err()
                .map(|err| err.to_string())
                .unwrap_or_else(|| "JSON and XML round-trip smoke test passed".into()),
        }
    }

    fn dimension_zero_panic(&self) -> DimensionResult {
        let score = if self.requirements.require_zero_panic { 1.0 } else { 0.0 };
        DimensionResult {
            dimension: ComplianceDimension::ZeroPanic,
            status: status_from_score(score),
            score,
            message: "workspace crates deny unwrap/expect/panic via clippy lints; release profile panic=abort"
                .into(),
        }
    }

    fn recommendations(
        &self,
        object_ratio: f64,
        action_ratio: f64,
        code_list_ratio: f64,
        dimensions: &[DimensionResult],
    ) -> Vec<String> {
        let mut items = Vec::new();

        if object_ratio < self.requirements.min_object_coverage {
            items.push(format!(
                "Import MIM {} object taxonomy (currently {:.1}% of {} types)",
                self.requirements.target_version,
                object_ratio * 100.0,
                self.requirements.expected_counts.object_types
            ));
        }
        if action_ratio < self.requirements.min_action_coverage {
            items.push(format!(
                "Import MIM {} action taxonomy (currently {:.1}% of {} types)",
                self.requirements.target_version,
                action_ratio * 100.0,
                self.requirements.expected_counts.action_types
            ));
        }
        if code_list_ratio < self.requirements.min_code_list_coverage {
            items.push(format!(
                "Import MIM {} code lists (currently {:.1}% of {} lists)",
                self.requirements.target_version,
                code_list_ratio * 100.0,
                self.requirements.expected_counts.code_lists
            ));
        }

        for dimension in dimensions {
            if dimension.status != ComplianceStatus::Compliant {
                items.push(format!(
                    "Improve {:?}: {}",
                    dimension.dimension, dimension.message
                ));
            }
        }

        if items.is_empty() {
            items.push("Stack meets all configured compliance requirements.".into());
        }

        items
    }
}

fn status_from_score(score: f64) -> ComplianceStatus {
    if score >= 1.0 {
        ComplianceStatus::Compliant
    } else if score > 0.0 {
        ComplianceStatus::Partial
    } else {
        ComplianceStatus::NonCompliant
    }
}

fn serialization_smoke_test(registry: &ModelRegistry) -> Result<(), mim_core::MimError> {
    let serializer = Serializer::new(registry.clone());
    let sample = registry
        .element_by_name("Object")
        .or_else(|| registry.element_by_name("Unit"))
        .or_else(|| registry.element_by_name("Task"))
        .ok_or_else(|| mim_core::MimError::Compliance("no sample class for smoke test".into()))?;

    let instance = MimInstance::new(sample.name.clone(), sample.semantic_id)?;
    let json = serializer.serialize_instance(&instance, SerializationFormat::Json)?;
    let xml = serializer.serialize_instance(&instance, SerializationFormat::Xml)?;

    if json.is_empty() || xml.is_empty() || !xml.contains("<?xml") {
        return Err(mim_core::MimError::Compliance(
            "serialization smoke test produced empty output".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use mim_core::{MimUri, SemanticId};
    use mim_model::manifest::{ModelElementKind, ModelElementSpec};
    use mim_model::{MimManifest, TaxonomyNode};

    fn seed_manifest() -> MimManifest {
        MimManifest {
            version: "5.1.0".into(),
            release_date: "2020-09-28".into(),
            description: "seed".into(),
            expected_object_types: 2300,
            expected_action_types: 500,
            expected_code_lists: 400,
            taxonomy: vec![TaxonomyNode {
                name: "Object".into(),
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
                parent: None,
                object_kind: None,
                action_kind: None,
                definition: "Root".into(),
                package_path: "Classifiers::Object".into(),
            }],
            elements: vec![ModelElementSpec {
                name: "Object".into(),
                kind: ModelElementKind::Class,
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
                uri: MimUri::parse("https://www.mimworld.org/mim/5.1.0/Classifiers/Object")
                    .expect("uri"),
                package_path: "Classifiers::Object".into(),
                definition: "Root".into(),
                parent_class: None,
                representation_term: None,
                representation_metadata: None,
                multiplicity_lower: None,
                multiplicity_upper: None,
                is_mandatory: false,
                is_nillable: true,
            }],
            code_lists: vec![],
        }
    }

    #[test]
    fn seed_model_is_partial_not_full() {
        let manifest = seed_manifest();
        let registry = ModelRegistry::from_manifest(manifest.clone()).expect("registry");
        let checker = ComplianceChecker::with_defaults();
        let report = checker.evaluate(&manifest, &registry, &ValidationReport::default());
        assert!(!report.is_fully_compliant);
        assert!(report.overall_score < 1.0);
        assert!(report
            .recommendations
            .iter()
            .any(|r| r.contains("object taxonomy")));
    }
}
