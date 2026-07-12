//! FMN coalition exercise — config-driven HTTPS federation with production PKI defaults.
//!
//! Uses `config/fmn-federation.toml` for peer URLs, mTLS client CA, and PKI env wiring.
//!
//! Run with:
//!   cargo run --example coalition_exercise
//!
//! Lab (conformance PKI):
//!   MIM_CONFORMANCE_KEYS=1 cargo run --example coalition_exercise

use ainextgenc2::{CoalitionExerciseScenario, MimStack, PolicyAccessDecision};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/fmn-federation.toml");
    std::env::set_var("MIM_FEDERATION_CONFIG", &config_path);

    let stack = MimStack::load()?;
    let scenario = CoalitionExerciseScenario::from_env()?;
    let output = tokio::runtime::Runtime::new()?.block_on(scenario.run(&stack))?;

    println!("FMN Coalition Exercise");
    println!("======================");
    println!("Federation node:     {}", scenario.federation().local_node.id);
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
        "USA-EYES-ONLY hidden from {}: {}",
        output.allied_nationality, output.usa_only_hidden_from_allied
    );
    println!();
    print_policy_plane(&output.policy_decisions);

    Ok(())
}

fn print_policy_plane(decisions: &[PolicyAccessDecision]) {
    println!("Policy plane (PIP → PDP → PEP)");
    println!("------------------------------");
    for phase in ["usa-national-c2-write", "gbr-allied-c2-read"] {
        let phase_decisions: Vec<_> = decisions.iter().filter(|d| d.phase == phase).collect();
        if phase_decisions.is_empty() {
            continue;
        }
        println!("{phase}:");
        for decision in phase_decisions {
            let resource = decision
                .resource_name
                .as_deref()
                .unwrap_or(&decision.resource_class);
            println!(
                "  PEP {} {} → {} {} REL [{}] @ {} → PDP {} ({})",
                decision.operation,
                decision.subject_id,
                decision.subject_nationality.as_deref().unwrap_or("-"),
                resource,
                decision.resource_releasability,
                decision.domain_id,
                decision.effect.to_uppercase(),
                decision.reason
            );
        }
    }
}
