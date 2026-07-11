//! Allied C2 sensor retrieval — USA national C2 publishes radar tracks; GBR allied C2 retrieves.
//!
//! Demonstrates the full MIP4-IES coalition flow:
//!   Sensor (SiteAirDefenceRadar) → USA national C2 (PutObject + journal)
//!   → ReplicationAgent sync → GBR allied C2 (GetByFilter + PEP nationality gate)
//!
//! Run with:
//!   cargo run --example allied_c2_sensor_retrieval

use ainextgenc2::{AlliedSensorRetrievalScenario, MimStack};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let stack = MimStack::load()?;
    let output = AlliedSensorRetrievalScenario::demo().run(&stack)?;

    println!("Allied C2 Sensor Track Retrieval Example");
    println!("========================================");
    println!("Sensor:              {}", output.sensor_name);
    println!(
        "National C2 ({}) published: {} MIM instances",
        output.usa_nationality, output.usa_published_count
    );
    println!(
        "Replication applied: {} journal entries",
        output.replication_applied
    );
    println!(
        "Allied C2 ({}) retrieved: {} targets, {} tracks",
        output.allied_nationality, output.gbr_target_count, output.gbr_track_count
    );
    println!(
        "HOSTILE-1 OID:       {}",
        output
            .hostile_track_oid
            .as_deref()
            .unwrap_or("(not visible to allied analyst)")
    );
    println!(
        "USA-EYES-ONLY hidden from {}: {}",
        output.allied_nationality, output.usa_only_hidden_from_allied
    );
    println!();
    println!("Retrieved coalition tracks/targets:");
    for item in &output.retrieved {
        let name = item.name.as_deref().unwrap_or("(track)");
        println!(
            "  {} {} [{}] oid={}",
            item.class_name, name, item.label, item.oid
        );
    }

    Ok(())
}
