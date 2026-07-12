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
    let production = std::env::args().any(|arg| arg == "--production");
    let output = if production {
        DcsCrossDomainScenario::demo().run(&stack)?
    } else {
        DcsCrossDomainScenario::demo().run_lab(&stack)?
    };

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
    println!(
        "ZTDF PEP decrypt: {}",
        if output.ztdf_pep_decrypt_verified {
            "VERIFIED"
        } else {
            "SKIPPED/FAILED"
        }
    );
    println!();
    println!("Audit records:    {}", output.audit_record_count);
    println!(
        "Audit chain:      {}",
        if output.audit_chain_verified {
            "VERIFIED"
        } else {
            "FAILED"
        }
    );
    if let Some(path) = &output.siem_export_path {
        println!("SIEM export:      {path}");
    }

    Ok(())
}
