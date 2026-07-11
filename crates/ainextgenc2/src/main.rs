use std::env;
use std::process;

use ainextgenc2::MimStack;
use mim_compliance::ComplianceDimension;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).map(String::as_str);

    let stack = match path {
        Some(p) => MimStack::load_path(p)?,
        None => MimStack::load()?,
    };

    let report = stack.compliance_report();

    println!("AINextGenC2 MIM Stack");
    println!("=====================");
    println!("Loaded model: {}", stack.registry().version());
    println!("Target:       {}", report.target_version);
    println!(
        "Coverage:     {} object types, {} action types, {} code lists",
        stack.registry().object_type_count(),
        stack.registry().action_type_count(),
        stack.registry().code_list_count()
    );
    println!(
        "Overall:      {:.1}% ({})",
        report.overall_score * 100.0,
        if report.is_fully_compliant {
            "FULLY COMPLIANT"
        } else {
            "NOT YET COMPLIANT"
        }
    );
    println!();
    println!("Dimensions:");
    for dimension in &report.dimensions {
        let status = match dimension.status {
            mim_compliance::ComplianceStatus::Compliant => "OK",
            mim_compliance::ComplianceStatus::Partial => "PARTIAL",
            mim_compliance::ComplianceStatus::NonCompliant => "FAIL",
        };
        println!(
            "  [{status}] {:?}: {:.0}% — {}",
            dimension.dimension,
            dimension.score * 100.0,
            dimension.message
        );
    }

    if let Some(coverage) = report.dimension(ComplianceDimension::ModelCoverage) {
        println!();
        println!("Model coverage detail: {}", coverage.message);
    }

    println!();
    println!("Recommendations:");
    for (idx, item) in report.recommendations.iter().enumerate() {
        println!("  {}. {item}", idx + 1);
    }

    if !report.is_fully_compliant {
        process::exit(2);
    }

    Ok(())
}
