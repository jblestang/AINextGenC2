//! Allied C2 sensor retrieval — USA national C2 publishes radar tracks; GBR allied C2 retrieves.
//!
//! Demonstrates the full MIP4-IES coalition flow:
//!   Sensor (SiteAirDefenceRadar) → USA national C2 (PutObject + journal)
//!   → Replication sync → GBR allied C2 (GetByFilter + PEP nationality gate)
//!
//! Run with:
//!   cargo run --example allied_c2_sensor_retrieval
//!
//! Remote HTTPS federation (lab):
//!   MIM_FEDERATION_HTTP=1 cargo run --example allied_c2_sensor_retrieval

use ainextgenc2::{AlliedSensorRetrievalScenario, FederationTransport, MimStack, PolicyAccessDecision};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let stack = MimStack::load()?;
    let uses_http = scenario_uses_http();
    let output = AlliedSensorRetrievalScenario::demo()
        .with_transport(select_transport())
        .run_federated(&stack)?;

    let mode = if uses_http {
        "HTTPS federation"
    } else {
        "in-process"
    };

    println!("Allied C2 Sensor Track Retrieval Example ({mode})");
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
    print_policy_plane(&output.policy_decisions);
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

fn scenario_uses_http() -> bool {
    std::env::var("MIM_FEDERATION_HTTP")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn select_transport() -> FederationTransport {
    if scenario_uses_http() {
        FederationTransport::Http
    } else {
        FederationTransport::InMemory
    }
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
