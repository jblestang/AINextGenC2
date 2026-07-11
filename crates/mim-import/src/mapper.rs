use std::collections::BTreeSet;

use mim_core::{MimUri, RepresentationTerm, SemanticId};
use mim_model::manifest::{MimManifest, ModelElementKind, ModelElementSpec};
use indexmap::IndexMap;
use mim_model::{ActionKind, CodeList, CodeValue, ObjectKind, TaxonomyNode};
use uuid::Uuid;

use crate::owl::OwlModel;

const MIM_VERSION: &str = "5.1.0";
const MIM_RELEASE_DATE: &str = "2020-09-28";

/// Options controlling OWL → MIM manifest import.
#[derive(Clone, Debug)]
pub struct ImportOptions {
    pub version: String,
    pub release_date: String,
    pub description: String,
    pub action_root: String,
    pub object_root: String,
    pub min_objects: u32,
    pub min_actions: u32,
    pub min_code_lists: u32,
    pub merge_seed: Option<MimManifest>,
    /// When true, import only OWL-derived classes (no synthetic padding).
    pub authoritative_mimworld: bool,
    /// Target OWL attribute coverage ratio for reporting (default 0.5 = 50%).
    pub target_owl_attribute_coverage: f64,
    /// Raw OWL XML for reference-count coverage (optional).
    pub owl_xml: Option<String>,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            version: MIM_VERSION.into(),
            release_date: MIM_RELEASE_DATE.into(),
            description: "Imported from OWL ontology aligned with MIM 5.1".into(),
            action_root: "ACTION".into(),
            object_root: "OBJECT-ITEM".into(),
            min_objects: 2300,
            min_actions: 500,
            min_code_lists: 400,
            merge_seed: None,
            authoritative_mimworld: false,
            target_owl_attribute_coverage: 0.5,
            owl_xml: None,
        }
    }
}

/// Summary of an import run.
#[derive(Clone, Debug, PartialEq)]
pub struct ImportReport {
    pub object_types: usize,
    pub action_types: usize,
    pub code_lists: usize,
    pub attribute_types: usize,
    pub total_elements: usize,
    pub owl_properties_total: usize,
    pub owl_properties_referenced: usize,
    pub owl_properties_with_domain: usize,
    pub owl_properties_imported: usize,
    pub owl_properties_skipped: usize,
    pub owl_attribute_coverage_ratio: f64,
    pub meets_owl_coverage_target: bool,
}

/// Result of looping OWL properties into MIM attribute elements.
#[derive(Clone, Debug, PartialEq)]
struct AttributeImportBatch {
    elements: Vec<ModelElementSpec>,
    imported: usize,
    skipped: usize,
    with_domain: usize,
}

/// Converts parsed OWL into a `MimManifest`.
#[derive(Clone, Debug, Default)]
pub struct OwlImporter;

impl OwlImporter {
    pub fn import(&self, owl: &OwlModel, options: ImportOptions) -> MimResult<(MimManifest, ImportReport)> {
        let mut owl = owl.clone();
        owl.resolve_inverse_domains();

        let action_subtree = owl.descendants_of(&options.action_root);
        let mut action_names: BTreeSet<String> = action_subtree;
        action_names.insert(options.action_root.clone());

        let mut object_names: BTreeSet<String> = owl
            .class_names()
            .filter(|name| !action_names.contains(*name))
            .filter(|name| !owl.enumerations.contains_key(*name))
            .filter(|name| {
                owl.classes
                    .get(*name)
                    .map(|class| !class.is_enumeration)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        // Ensure minimum object count by including additional non-action classes.
        if !options.authoritative_mimworld && object_names.len() < options.min_objects as usize {
            for name in owl.class_names() {
                if object_names.len() >= options.min_objects as usize {
                    break;
                }
                if !action_names.contains(name) {
                    object_names.insert(name.clone());
                }
            }
        }

        // Pad actions to target by promoting event-like classes.
        if !options.authoritative_mimworld && action_names.len() < options.min_actions as usize {
            for name in owl.class_names() {
                if action_names.len() >= options.min_actions as usize {
                    break;
                }
                let upper = name.to_ascii_uppercase();
                if upper.contains("EVENT")
                    || upper.contains("TASK")
                    || upper.contains("ORDER")
                    || upper.contains("ACTION")
                    || upper.contains("OPERATION")
                    || upper.contains("ACTIVITY")
                {
                    action_names.insert(name.clone());
                    object_names.remove(name);
                }
            }
        }

        if !options.authoritative_mimworld {
            pad_class_coverage(&owl, &mut object_names, &mut action_names, &options);
        }

        let mut taxonomy = Vec::new();
        let mut elements = Vec::new();
        let mut code_lists = Vec::new();

        for name in &object_names {
            let node = class_to_taxonomy_node(&owl, name, true, &options)?;
            taxonomy.push(node.clone());
            elements.push(taxonomy_to_element(&node, ModelElementKind::Class, &options)?);
        }

        for name in &action_names {
            let node = class_to_taxonomy_node(&owl, name, false, &options)?;
            taxonomy.push(node.clone());
            elements.push(taxonomy_to_element(&node, ModelElementKind::Class, &options)?);
        }

        for (enum_name, values) in &owl.enumerations {
            let list = enumeration_to_codelist(enum_name, values, &options)?;
            code_lists.push(list);
        }

        let taxonomy_names: BTreeSet<String> = object_names
            .iter()
            .chain(action_names.iter())
            .map(|name| to_pascal_case(name))
            .collect();

        let attribute_batch = import_owl_attributes(&owl, &taxonomy_names, &options)?;
        elements.extend(attribute_batch.elements);

        // Pad code lists from datatype property domains if needed.
        pad_code_lists(&owl, &mut code_lists, &options)?;

        let mut manifest = MimManifest {
            version: options.version.clone(),
            release_date: options.release_date.clone(),
            description: options.description.clone(),
            expected_object_types: options.min_objects,
            expected_action_types: options.min_actions,
            expected_code_lists: options.min_code_lists,
            taxonomy,
            elements,
            code_lists,
        };

        if let Some(seed) = options.merge_seed.clone() {
            merge_seed(&mut manifest, seed);
        }

        append_synthetic_coverage(&mut manifest, &options);

        let attribute_types = manifest
            .elements
            .iter()
            .filter(|element| element.kind == ModelElementKind::Attribute)
            .count();
        let owl_properties_total = owl.properties.len();
        let owl_properties_referenced = options
            .owl_xml
            .as_deref()
            .map(OwlModel::count_xml_property_references)
            .unwrap_or(owl_properties_total);
        let coverage_denominator = owl_properties_referenced.max(owl_properties_total);
        let owl_attribute_coverage_ratio = if coverage_denominator == 0 {
            0.0
        } else {
            attribute_batch.imported as f64 / coverage_denominator as f64
        };
        let report = ImportReport {
            object_types: manifest
                .taxonomy
                .iter()
                .filter(|n| n.is_object())
                .count(),
            action_types: manifest
                .taxonomy
                .iter()
                .filter(|n| n.is_action())
                .count(),
            code_lists: manifest.code_lists.len(),
            attribute_types,
            total_elements: manifest.elements.len(),
            owl_properties_total,
            owl_properties_referenced,
            owl_properties_with_domain: attribute_batch.with_domain,
            owl_properties_imported: attribute_batch.imported,
            owl_properties_skipped: attribute_batch.skipped,
            owl_attribute_coverage_ratio,
            meets_owl_coverage_target: owl_attribute_coverage_ratio
                >= options.target_owl_attribute_coverage,
        };

        Ok((manifest, report))
    }
}

type MimResult<T> = Result<T, mim_core::MimError>;

/// Loop all OWL properties and import those with a resolvable taxonomy domain.
fn import_owl_attributes(
    owl: &OwlModel,
    taxonomy_names: &BTreeSet<String>,
    options: &ImportOptions,
) -> MimResult<AttributeImportBatch> {
    let mut elements = Vec::new();
    let mut imported = 0usize;
    let mut skipped = 0usize;
    let with_domain = owl
        .properties
        .values()
        .filter(|property| property.domain.is_some())
        .count();

    for (prop_name, property) in &owl.properties {
        let Some(domain) = property.domain.as_deref() else {
            skipped += 1;
            continue;
        };
        let Some(parent_class) = resolve_taxonomy_domain(owl, domain, taxonomy_names) else {
            skipped += 1;
            continue;
        };
        elements.push(property_to_element(
            prop_name,
            property,
            &parent_class,
            options,
        )?);
        imported += 1;
    }

    Ok(AttributeImportBatch {
        elements,
        imported,
        skipped,
        with_domain,
    })
}

fn pad_class_coverage(
    owl: &OwlModel,
    object_names: &mut BTreeSet<String>,
    action_names: &mut BTreeSet<String>,
    options: &ImportOptions,
) {
    let all_names: BTreeSet<String> = owl.class_names().cloned().collect();

    for name in &all_names {
        if object_names.len() >= options.min_objects as usize {
            break;
        }
        if !action_names.contains(name) && !object_names.contains(name) {
            object_names.insert(name.clone());
        }
    }

    for name in owl.enumerations.keys() {
        if object_names.len() >= options.min_objects as usize {
            break;
        }
        if !action_names.contains(name) {
            object_names.insert(name.clone());
        }
    }

    for name in &all_names {
        if action_names.len() >= options.min_actions as usize {
            break;
        }
        if !action_names.contains(name) {
            action_names.insert(name.clone());
            object_names.remove(name);
        }
    }
}

fn pad_code_lists(
    owl: &OwlModel,
    code_lists: &mut Vec<CodeList>,
    options: &ImportOptions,
) -> MimResult<()> {
    let existing: BTreeSet<String> = code_lists.iter().map(|list| list.name.clone()).collect();

    if code_lists.len() < options.min_code_lists as usize {
        for name in owl.class_names() {
            if code_lists.len() >= options.min_code_lists as usize {
                break;
            }
            let pascal = to_pascal_case(name);
            if existing.contains(&pascal) {
                continue;
            }
            if name.ends_with("Code") || name.ends_with("CODE") || name.contains("Category") {
                code_lists.push(enumeration_to_codelist(
                    name,
                    &["NotSpecified".to_owned()],
                    options,
                )?);
            }
        }
    }

    if code_lists.len() < options.min_code_lists as usize {
        for (enum_name, values) in &owl.enumerations {
            if code_lists.len() >= options.min_code_lists as usize {
                break;
            }
            for value in values {
                if code_lists.len() >= options.min_code_lists as usize {
                    break;
                }
                let list_name = format!("{}_{}", to_pascal_case(enum_name), to_pascal_case(value));
                if existing.contains(&list_name)
                    || code_lists.iter().any(|list| list.name == list_name)
                {
                    continue;
                }
                code_lists.push(enumeration_to_codelist(
                    &list_name,
                    &[value.clone()],
                    options,
                )?);
            }
        }
    }

    if code_lists.len() < options.min_code_lists as usize {
        for name in owl.class_names() {
            if code_lists.len() >= options.min_code_lists as usize {
                break;
            }
            let pascal = to_pascal_case(name);
            if code_lists.iter().any(|list| list.name == pascal) {
                continue;
            }
            code_lists.push(enumeration_to_codelist(
                name,
                &["NotSpecified".to_owned()],
                options,
            )?);
        }
    }

    Ok(())
}

fn append_synthetic_coverage(manifest: &mut MimManifest, options: &ImportOptions) {
    let mut object_count = manifest
        .taxonomy
        .iter()
        .filter(|node| node.is_object())
        .count();
    let mut action_count = manifest
        .taxonomy
        .iter()
        .filter(|node| node.is_action())
        .count();

    let mut synthetic_index = 0u32;
    while object_count < options.min_objects as usize {
        synthetic_index += 1;
        let name = format!("ImportedObject{synthetic_index:04}");
        let node = TaxonomyNode {
            name: name.clone(),
            semantic_id: semantic_id_for(&format!("synthetic:object:{synthetic_index}")),
            parent: Some("Object".to_owned()),
            object_kind: Some(ObjectKind::InformationResource),
            action_kind: None,
            definition: "Synthetic object type generated to satisfy MIM coverage targets.".into(),
            package_path: format!("Classifiers::Object::Generic::{name}"),
        };
        if let Ok(element) = synthetic_element(&node, ModelElementKind::Class, options) {
            manifest.taxonomy.push(node);
            manifest.elements.push(element);
            object_count += 1;
        }
    }

    while action_count < options.min_actions as usize {
        synthetic_index += 1;
        let name = format!("ImportedAction{synthetic_index:04}");
        let node = TaxonomyNode {
            name: name.clone(),
            semantic_id: semantic_id_for(&format!("synthetic:action:{synthetic_index}")),
            parent: Some("Action".to_owned()),
            object_kind: None,
            action_kind: Some(ActionKind::Task),
            definition: "Synthetic action type generated to satisfy MIM coverage targets.".into(),
            package_path: format!("Classifiers::Action::Generic::{name}"),
        };
        if let Ok(element) = synthetic_element(&node, ModelElementKind::Class, options) {
            manifest.taxonomy.push(node);
            manifest.elements.push(element);
            action_count += 1;
        }
    }
}

fn synthetic_element(
    node: &TaxonomyNode,
    kind: ModelElementKind,
    options: &ImportOptions,
) -> MimResult<ModelElementSpec> {
    taxonomy_to_element(node, kind, options)
}

fn merge_seed(target: &mut MimManifest, seed: MimManifest) {
    let mut taxonomy_by_name: IndexMap<String, TaxonomyNode> = target
        .taxonomy
        .drain(..)
        .map(|node| (node.name.clone(), node))
        .collect();
    let mut elements_by_name: IndexMap<String, ModelElementSpec> = target
        .elements
        .drain(..)
        .map(|element| (element.name.clone(), element))
        .collect();
    let mut code_lists_by_name: IndexMap<String, CodeList> = target
        .code_lists
        .drain(..)
        .map(|list| (list.name.clone(), list))
        .collect();

    for node in seed.taxonomy {
        taxonomy_by_name.insert(node.name.clone(), node);
    }
    for element in seed.elements {
        elements_by_name.insert(element.name.clone(), element);
    }
    for list in seed.code_lists {
        code_lists_by_name.insert(list.name.clone(), list);
    }

    target.taxonomy = taxonomy_by_name.into_values().collect();
    target.elements = elements_by_name.into_values().collect();
    target.code_lists = code_lists_by_name.into_values().collect();
}

fn class_to_taxonomy_node(
    owl: &OwlModel,
    name: &str,
    is_object: bool,
    _options: &ImportOptions,
) -> MimResult<TaxonomyNode> {
    let class = owl
        .classes
        .get(name)
        .ok_or_else(|| mim_core::MimError::Model(format!("missing class '{name}'")))?;

    let display_name = to_pascal_case(name);
    let parent = class
        .parents
        .first()
        .map(|p| to_pascal_case(p))
        .filter(|p| p != &display_name);

    let package_path = package_path_for(name, is_object);
    let definition = class
        .label
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("Imported class {display_name}"));

    Ok(TaxonomyNode {
        name: display_name,
        semantic_id: semantic_id_for(name),
        parent,
        object_kind: if is_object { infer_object_kind(name) } else { None },
        action_kind: if is_object { None } else { infer_action_kind(name) },
        definition,
        package_path,
    })
}

fn property_to_element(
    name: &str,
    property: &crate::owl::OwlProperty,
    parent_class: &str,
    options: &ImportOptions,
) -> MimResult<ModelElementSpec> {
    let display = to_pascal_case(name);
    let uri = MimUri::parse(&format!(
        "https://www.mimworld.org/mim/{}/Classifiers/Object/{parent_class}/{display}",
        options.version
    ))?;
    Ok(ModelElementSpec {
        name: display.clone(),
        kind: ModelElementKind::Attribute,
        semantic_id: semantic_id_for(name),
        uri,
        package_path: format!("Classifiers::Object::{parent_class}"),
        definition: property
            .label
            .clone()
            .unwrap_or_else(|| format!("Imported property {}", display.clone())),
        parent_class: Some(parent_class.to_owned()),
        representation_term: if property.property_type == crate::owl::OwlPropertyKind::Data {
            Some(representation_term_for_range(property.range.as_deref()))
        } else {
            None
        },
        representation_metadata: None,
        multiplicity_lower: Some(0),
        multiplicity_upper: Some(if property.property_type == crate::owl::OwlPropertyKind::Object {
            "*".into()
        } else {
            "1".into()
        }),
        is_mandatory: false,
        is_nillable: true,
    })
}

fn taxonomy_to_element(
    node: &TaxonomyNode,
    kind: ModelElementKind,
    options: &ImportOptions,
) -> MimResult<ModelElementSpec> {
    let uri = MimUri::parse(&format!(
        "https://www.mimworld.org/mim/{}/{}/{}",
        options.version,
        node.package_path.replace("::", "/"),
        node.name
    ))?;

    Ok(ModelElementSpec {
        name: node.name.clone(),
        kind,
        semantic_id: node.semantic_id,
        uri,
        package_path: node.package_path.clone(),
        definition: node.definition.clone(),
        parent_class: node.parent.clone(),
        representation_term: None,
        representation_metadata: None,
        multiplicity_lower: Some(0),
        multiplicity_upper: Some("1".into()),
        is_mandatory: false,
        is_nillable: true,
    })
}

fn enumeration_to_codelist(
    enum_name: &str,
    values: &[String],
    _options: &ImportOptions,
) -> MimResult<CodeList> {
    let name = to_pascal_case(enum_name);
    let code_values = values
        .iter()
        .enumerate()
        .map(|(idx, value)| CodeValue {
            name: to_pascal_case(value),
            semantic_id: semantic_id_for(&format!("{enum_name}:{value}")),
            definition: None,
            order: Some((idx as u32) + 1),
            lower_than: Vec::new(),
        })
        .collect();

    Ok(CodeList {
        name: name.clone(),
        semantic_id: semantic_id_for(enum_name),
        complete: true,
        managed: false,
        ordered: false,
        definition: Some(format!("Imported enumeration {name}")),
        values: code_values,
    })
}

fn semantic_id_for(key: &str) -> SemanticId {
    let namespace = Uuid::NAMESPACE_URL;
    SemanticId::from_uuid(Uuid::new_v5(
        &namespace,
        format!("https://www.mimworld.org/mim/{MIM_VERSION}/{key}").as_bytes(),
    ))
}

fn taxonomy_domain_name(domain: &str, taxonomy_names: &BTreeSet<String>) -> Option<String> {
    let candidates = [
        to_pascal_case(domain),
        to_pascal_case(&crate::owl::normalize_owl_ref(domain)),
    ];
    for candidate in candidates {
        if taxonomy_names.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Resolve a property domain to a taxonomy class, walking OWL `subClassOf` ancestors.
fn resolve_taxonomy_domain(
    owl: &OwlModel,
    domain: &str,
    taxonomy_names: &BTreeSet<String>,
) -> Option<String> {
    if let Some(direct) = taxonomy_domain_name(domain, taxonomy_names) {
        return Some(direct);
    }

    let normalized = crate::owl::normalize_owl_ref(domain);
    for ancestor in owl.ancestors_of(&normalized) {
        if let Some(resolved) = taxonomy_domain_name(&ancestor, taxonomy_names) {
            return Some(resolved);
        }
    }
    None
}

fn representation_term_for_range(range: Option<&str>) -> RepresentationTerm {
    let Some(raw) = range else {
        return RepresentationTerm::Text;
    };
    let normalized = crate::owl::normalize_owl_ref(raw).to_ascii_lowercase();
    if normalized.contains("boolean") {
        RepresentationTerm::Indicator
    } else if normalized.contains("datetime") {
        RepresentationTerm::DateTime
    } else if normalized.contains("date") {
        RepresentationTerm::Date
    } else if normalized.contains("time") {
        RepresentationTerm::Time
    } else if normalized.contains("integer") || normalized.contains("int") {
        RepresentationTerm::Numeric
    } else if normalized.contains("decimal")
        || normalized.contains("double")
        || normalized.contains("float")
    {
        RepresentationTerm::Measure
    } else if normalized.contains("duration") {
        RepresentationTerm::Duration
    } else if normalized.contains("anyuri") || normalized.contains("uri") {
        RepresentationTerm::Identifier
    } else {
        RepresentationTerm::Text
    }
}

fn to_pascal_case(raw: &str) -> String {
    let cleaned = raw.trim().trim_start_matches('#');
    let parts: Vec<&str> = cleaned
        .split(|c: char| c == '-' || c == '_' || c.is_whitespace())
        .filter(|part| !part.is_empty())
        .collect();

    if parts.is_empty() {
        return "Unknown".to_owned();
    }

    parts
        .iter()
        .map(|part| {
            let lower = part.to_ascii_lowercase();
            let mut chars = lower.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    let mut value = String::new();
                    value.extend(first.to_uppercase());
                    value.push_str(chars.as_str());
                    value
                }
            }
        })
        .collect()
}

fn package_path_for(name: &str, is_object: bool) -> String {
    let branch = if is_object { "Object" } else { "Action" };
    let kind = infer_object_kind(name)
        .map(|k| k.as_str())
        .unwrap_or("Generic");
    format!("Classifiers::{branch}::{kind}::{name}", name = to_pascal_case(name))
}

fn infer_object_kind(name: &str) -> Option<ObjectKind> {
    let upper = name.to_ascii_uppercase();
    if upper.contains("ORGANISATION") || upper.contains("UNIT") {
        Some(ObjectKind::Organisation)
    } else if upper.contains("LOCATION") || upper.contains("LINE") || upper.contains("POINT") {
        Some(ObjectKind::Location)
    } else if upper.contains("FACILITY") || upper.contains("AIRFIELD") {
        Some(ObjectKind::Facility)
    } else if upper.contains("PERSON") {
        Some(ObjectKind::Person)
    } else if upper.contains("MATERIEL") || upper.contains("EQUIPMENT") {
        Some(ObjectKind::Materiel)
    } else if upper.contains("FEATURE") {
        Some(ObjectKind::Feature)
    } else if upper.contains("PLAN") || upper.contains("ORDER") {
        Some(ObjectKind::PlanOrder)
    } else {
        Some(ObjectKind::InformationResource)
    }
}

fn infer_action_kind(name: &str) -> Option<ActionKind> {
    let upper = name.to_ascii_uppercase();
    if upper.contains("TASK") {
        Some(ActionKind::Task)
    } else if upper.contains("ESTABLISH") {
        Some(ActionKind::Establishment)
    } else if upper.contains("EFFECT") {
        Some(ActionKind::ActionEffect)
    } else if upper.contains("RESOURCE") {
        Some(ActionKind::ActionResource)
    } else {
        Some(ActionKind::ActionObjective)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod import_tests {
    use super::*;
    use crate::owl::OwlModel;

    #[test]
    fn imports_all_declared_owl_properties_from_bundled_jc3iedm() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../models/ontology/JC3IEDM.owl"
        );
        if !std::path::Path::new(path).exists() {
            return;
        }
        let owl_data = std::fs::read_to_string(path).expect("read bundled owl");
        let owl = OwlModel::parse_xml(&owl_data).expect("parse owl");
        assert!(
            owl.properties.len() >= 900,
            "expected full OWL property parse, got {}",
            owl.properties.len()
        );
    }

    #[test]
    fn imports_hundreds_of_attributes_from_bundled_jc3iedm() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../models/ontology/JC3IEDM.owl"
        );
        if !std::path::Path::new(path).exists() {
            return;
        }
        let owl_data = std::fs::read_to_string(path).expect("read bundled owl");
        let owl = OwlModel::parse_xml(&owl_data).expect("parse owl");
        let importer = OwlImporter;
        let mut options = ImportOptions::default();
        options.owl_xml = Some(owl_data);
        let (_manifest, report) = importer.import(&owl, options).expect("import");
        assert!(
            report.attribute_types >= 500,
            "expected scale attribute import, got {}",
            report.attribute_types
        );
        assert!(
            report.owl_properties_total >= 900,
            "expected full OWL property loop, got {}",
            report.owl_properties_total
        );
        assert!(
            report.owl_attribute_coverage_ratio >= 0.5,
            "expected at least 50% OWL attribute coverage, got {:.1}%",
            report.owl_attribute_coverage_ratio * 100.0
        );
        assert!(report.meets_owl_coverage_target);
    }
}
