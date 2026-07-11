//! SITAC simulator — 4 radars, FCS with 4 TELs, national C2 ingest, coalition long-range share.
//!
//! Run with:
//!   cargo run --example sitac_simulator

use ainextgenc2::{SitacSimulatorScenario, MimStack};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let stack = MimStack::load()?;
    let output = SitacSimulatorScenario::demo().run(&stack)?;

    println!("SITAC Simulator — National IADS Picture");
    println!("=====================================");
    println!("Radars ({}):", output.radar_count);
    for radar in &output.radars {
        println!("  - {radar}");
    }
    println!("TELs ({}):", output.tel_count);
    for tel in &output.tels {
        println!("  - {tel}");
    }
    println!();
    println!(
        "National C2 ({}) published: {} MIM instances",
        output.national_c2_domain, output.national_published_count
    );
    println!(
        "Replication applied: {} journal entries",
        output.replication_applied
    );
    println!(
        "National targets visible: {}",
        output.national_target_count
    );
    println!(
        "Allied C2 ({}) targets visible: {} (long-range shared: {})",
        output.allied_c2_domain,
        output.allied_target_count,
        output.long_range_shared_count
    );
    println!(
        "National-only tracks hidden from allied: {}",
        output.national_only_hidden_from_allied
    );
    println!();
    println!("National C2 target picture:");
    for target in &output.national_targets {
        let name = target.name.as_deref().unwrap_or("(unnamed)");
        let source = target
            .source_radar
            .as_deref()
            .unwrap_or("(unknown source)");
        let share = if target.coalition_visible {
            "COALITION"
        } else {
            "NATIONAL-ONLY"
        };
        println!("  {name} [{share}] source={source}");
    }
    println!();
    println!("Allied C2 target picture (long-range only):");
    for target in &output.allied_targets {
        let name = target.name.as_deref().unwrap_or("(unnamed)");
        println!("  {name}");
    }

    Ok(())
}
