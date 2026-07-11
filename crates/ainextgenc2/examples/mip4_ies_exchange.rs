//! MIP4-IES transport example — publish radar detections via exchange broker.
//!
//! Run with:
//!   cargo run --example mip4_ies_exchange

use ainextgenc2::{MimStack, TransportExchangeScenario};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let stack = MimStack::load()?;
    let output = TransportExchangeScenario::demo().run(&stack)?;

    println!("MIP4-IES Transport Exchange Example");
    println!("===================================");
    println!("Published:  {} instances", output.published_count);
    println!("Targets:    {}", output.target_count);
    println!(
        "HOSTILE-1:  {}",
        output.hostile_track.as_deref().unwrap_or("(not found)")
    );
    println!();
    println!("Active exchange JSON:");
    println!("{}", output.exchange_json);

    Ok(())
}
