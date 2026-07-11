use std::process;

use mim_import::{
    load_owl_source, ImportOptions, OwlImporter, OwlModel, MIMWORLD_JC3IEDM_OWL_URL,
};
use mim_model::MimManifest;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut owl_path = None;
    let mut source = None;
    let mut output_path = std::path::PathBuf::from("models/mim-full-5.1.json");
    let mut merge_seed_path = Some(std::path::PathBuf::from("models/mim-core-5.1.json"));

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--owl" => owl_path = args.next(),
            "--source" => source = args.next(),
            "--output" => output_path = std::path::PathBuf::from(args.next().ok_or("missing --output value")?),
            "--merge" => merge_seed_path = Some(std::path::PathBuf::from(args.next().ok_or("missing --merge value")?)),
            "--no-merge" => merge_seed_path = None,
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let owl_data = match (source.as_deref(), owl_path.as_deref()) {
        (Some(src), None) => load_owl_source(src)?,
        (None, Some(path)) => load_owl_source(path)?,
        (Some("mimworld"), Some(path)) => std::fs::read_to_string(path)?,
        _ => return Err(format!(
            "specify --source mimworld or --owl <path> (mimworld JC3IEDM: {MIMWORLD_JC3IEDM_OWL_URL})"
        ).into()),
    };

    let owl = OwlModel::parse_xml(&owl_data)?;
    let mut options = ImportOptions::default();
    options.owl_xml = Some(owl_data);
    if source.as_deref() == Some("mimworld") || source.as_deref() == Some("mimworld:jc3iedm") {
        options.authoritative_mimworld = true;
        options.description = "Imported from mimworld.org JC3IEDM OWL (authoritative MIP source)".into();
    }
    if let Some(seed_path) = merge_seed_path {
        let seed_data = std::fs::read_to_string(seed_path)?;
        options.merge_seed = Some(MimManifest::from_json(&seed_data)?);
    }

    let importer = OwlImporter;
    let coverage_target = options.target_owl_attribute_coverage;
    let (manifest, report) = importer.import(&owl, options)?;

    let json = serde_json::to_string_pretty(&manifest)?;
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output_path, json)?;

    println!("Imported manifest written to {}", output_path.display());
    println!(
        "objects={} actions={} code_lists={} attributes={} elements={}",
        report.object_types,
        report.action_types,
        report.code_lists,
        report.attribute_types,
        report.total_elements
    );
    println!(
        "owl_properties={} xml_tag_lines={} with_domain={} imported={} skipped={} coverage={:.1}% target={:.0}% ({})",
        report.owl_properties_total,
        report.owl_properties_referenced,
        report.owl_properties_with_domain,
        report.owl_properties_imported,
        report.owl_properties_skipped,
        report.owl_attribute_coverage_ratio * 100.0,
        coverage_target * 100.0,
        if report.meets_owl_coverage_target {
            "MET"
        } else {
            "BELOW TARGET"
        }
    );

    Ok(())
}
