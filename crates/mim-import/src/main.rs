use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process;

use mim_import::{ImportOptions, OwlImporter, OwlModel};
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
    let mut output_path = PathBuf::from("models/mim-full-5.1.json");
    let mut merge_seed_path = Some(PathBuf::from("models/mim-core-5.1.json"));

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--owl" => owl_path = args.next(),
            "--output" => output_path = PathBuf::from(args.next().ok_or("missing --output value")?),
            "--merge" => merge_seed_path = Some(PathBuf::from(args.next().ok_or("missing --merge value")?)),
            "--no-merge" => merge_seed_path = None,
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let owl_path = owl_path.ok_or("missing required --owl <path>")?;
    let mut file = fs::File::open(&owl_path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;

    let owl = OwlModel::parse_xml(&data)?;
    let mut options = ImportOptions::default();
    if let Some(seed_path) = merge_seed_path {
        let seed_data = fs::read_to_string(seed_path)?;
        options.merge_seed = Some(MimManifest::from_json(&seed_data)?);
    }

    let importer = OwlImporter;
    let (manifest, report) = importer.import(&owl, options)?;

    let json = serde_json::to_string_pretty(&manifest)?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, json)?;

    println!("Imported manifest written to {}", output_path.display());
    println!(
        "objects={} actions={} code_lists={} elements={}",
        report.object_types, report.action_types, report.code_lists, report.total_elements
    );

    Ok(())
}
