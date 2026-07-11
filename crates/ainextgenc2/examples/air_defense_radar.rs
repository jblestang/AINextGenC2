//! Air defense radar example — outputs MIM target/track detections.
//!
//! Run with:
//!   cargo run --example air_defense_radar

use ainextgenc2::{AirDefenseRadarScenario, MimStack};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let stack = MimStack::load()?;
    let output = AirDefenseRadarScenario::demo().run(&stack)?;

    println!("Air Defense Radar Detection Example");
    println!("=================================");
    println!("Radar:      {}", output.radar_name);
    println!("Tracks:     {}", output.detections.len());
    println!(
        "Validation: {} ({} errors)",
        if output.validation.is_valid {
            "valid"
        } else {
            "invalid"
        },
        output.validation.error_count
    );
    println!();
    println!("Detections:");
    for detection in &output.detections {
        println!(
            "  T{:03} {} @ {:.4},{:.4} alt {}m {}kt hdg {}° IFF {}",
            detection.track_number,
            detection.call_sign,
            detection.latitude,
            detection.longitude,
            detection.altitude_metres as u32,
            detection.speed_knots as u32,
            detection.heading_degrees as u32,
            detection.iff_mode
        );
    }
    println!();
    println!("MIM exchange JSON:");
    println!("{}", output.exchange_json);

    Ok(())
}
