use std::env;
use std::process;

use ainextgenc2::MimStack;
use mim_adatp_conformance::AdatpConformanceRunner;
use mim_mip4_conformance::Mip4ConformanceRunner;
use mim_compliance::ComplianceDimension;
use mim_labeling_compliance::LabelingComplianceChecker;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let labeling_only = args.iter().any(|a| a == "--labeling");
    let adatp_only = args.iter().any(|a| a == "--adatp");
    let mip4_only = args.iter().any(|a| a == "--mip4");
    let path = args.get(1).filter(|a| !a.starts_with("--")).map(String::as_str);

    if mip4_only {
        return run_mip4_conformance();
    }

    if adatp_only {
        return run_adatp_conformance();
    }

    if labeling_only {
        return run_labeling_compliance();
    }

    let stack = match path {
        Some(p) => MimStack::load_path(p)?,
        None => MimStack::load()?,
    };

    let report = stack.compliance_report();
    let labeling = stack.labeling_compliance_report();

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
        "MIM:          {:.1}% ({})",
        report.overall_score * 100.0,
        if report.is_fully_compliant {
            "FULLY COMPLIANT"
        } else {
            "NOT YET COMPLIANT"
        }
    );
    println!(
        "Labeling:     {:.1}% ({})",
        labeling.overall_score * 100.0,
        if labeling.is_fully_compliant {
            "FULLY COMPLIANT"
        } else {
            "NOT YET COMPLIANT"
        }
    );
    println!();
    println!("MIM Dimensions:");
    for dimension in &report.dimensions {
        print_dimension(
            &format!("{dimension:?}"),
            dimension.score,
            &dimension.message,
            dimension.status == mim_compliance::ComplianceStatus::Compliant,
        );
    }

    println!();
    println!("Labeling Dimensions (STANAG 4774/4778, ZTDF, DCS):");
    for dimension in &labeling.dimensions {
        let ok = dimension.status == mim_labeling_compliance::LabelingComplianceStatus::Compliant;
        print_dimension(
            &format!("{:?}", dimension.dimension),
            dimension.score,
            &dimension.message,
            ok,
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
    for item in &labeling.recommendations {
        if !report.recommendations.iter().any(|r| r == item) {
            println!("  -. {item}");
        }
    }

    if !report.is_fully_compliant || !labeling.is_fully_compliant {
        process::exit(2);
    }

    Ok(())
}

fn run_labeling_compliance() -> Result<(), Box<dyn std::error::Error>> {
    let report = LabelingComplianceChecker::with_defaults().evaluate();
    println!("Labeling Compliance (STANAG 4774/4778, ZTDF, DCS)");
    println!("================================================");
    println!(
        "Overall: {:.1}% ({})",
        report.overall_score * 100.0,
        if report.is_fully_compliant {
            "FULLY COMPLIANT"
        } else {
            "NOT YET COMPLIANT"
        }
    );
    for dimension in &report.dimensions {
        let ok = dimension.status == mim_labeling_compliance::LabelingComplianceStatus::Compliant;
        print_dimension(
            &format!("{:?}", dimension.dimension),
            dimension.score,
            &dimension.message,
            ok,
        );
    }
    if !report.is_fully_compliant {
        process::exit(2);
    }
    Ok(())
}

fn run_mip4_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let report = Mip4ConformanceRunner::new().evaluate();
    println!("MIP4-IES Conformance (FMN accreditation path)");
    println!("==============================================");
    println!(
        "Overall: {:.1}% — {}/{} tests ({})",
        report.overall_score * 100.0,
        report.total_passed(),
        report.total_tests(),
        if report.is_fully_compliant {
            "FULLY COMPLIANT"
        } else {
            "NOT YET COMPLIANT"
        }
    );
    println!();
    for suite in &report.suites {
        let status = if suite.failed == 0 { "OK" } else { "FAIL" };
        println!(
            "  [{status}] {}: {}/{} passed",
            suite.name, suite.passed, suite.total
        );
        for test in &suite.tests {
            let test_status = if test.passed { "pass" } else { "FAIL" };
            println!("      [{test_status}] {} — {}", test.id, test.message);
        }
    }
    if !report.recommendations.is_empty() {
        println!();
        println!("Recommendations:");
        for (idx, item) in report.recommendations.iter().enumerate() {
            println!("  {}. {item}", idx + 1);
        }
    }
    if !report.is_fully_compliant {
        process::exit(2);
    }
    Ok(())
}

fn run_adatp_conformance() -> Result<(), Box<dyn std::error::Error>> {
    let report = AdatpConformanceRunner::new().evaluate();
    println!("NATO ADatP Conformance (STANAG 4774/4778, ZTDF)");
    println!("================================================");
    println!(
        "Overall: {:.1}% — {}/{} tests ({})",
        report.overall_score * 100.0,
        report.total_passed(),
        report.total_tests(),
        if report.is_fully_compliant {
            "FULLY COMPLIANT"
        } else {
            "NOT YET COMPLIANT"
        }
    );
    println!();
    for suite in &report.suites {
        let status = if suite.failed == 0 { "OK" } else { "FAIL" };
        println!(
            "  [{status}] {}: {}/{} passed",
            suite.name, suite.passed, suite.total
        );
        for test in &suite.tests {
            let test_status = if test.passed { "pass" } else { "FAIL" };
            println!("      [{test_status}] {} — {}", test.id, test.message);
        }
    }
    if !report.recommendations.is_empty() {
        println!();
        println!("Recommendations:");
        for (idx, item) in report.recommendations.iter().enumerate() {
            println!("  {}. {item}", idx + 1);
        }
    }
    if !report.is_fully_compliant {
        process::exit(2);
    }
    Ok(())
}

fn print_dimension(name: &str, score: f64, message: &str, compliant: bool) {
    let status = if compliant { "OK" } else { "FAIL" };
    println!("  [{status}] {name}: {:.0}% — {message}", score * 100.0);
}
