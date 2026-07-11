//! DCS cross-domain scenario — labels MIM radar data with STANAG 4774/4778/ZTDF.
//!
//! Run with:
//!   cargo run --example dcs_cross_domain

use ainextgenc2::{DcsCrossDomainScenario, MimStack};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let stack = MimStack::load()?;
    let output = DcsCrossDomainScenario::demo().run(&stack)?;

    println!("DCS Cross-Domain Labeling Example");
    println!("=================================");
    println!("Source label:     {}", output.source_label);
    println!("Transfer:         {}", output.transfer_decision);
    println!("Reason:           {}", output.transfer_reason);
    println!(
        "Labeling stack:   {}",
        if output.labeling_compliant {
            "FULLY COMPLIANT"
        } else {
            "NOT COMPLIANT"
        }
    );
    println!();
    if let Some(xml) = &output.label_xml {
        println!("STANAG 4774 label (downgraded):");
        println!("{xml}");
        println!();
    }
    if let Some(manifest) = &output.ztdf_manifest {
        println!("ZTDF manifest:");
        println!("{manifest}");
    }

    Ok(())
}
