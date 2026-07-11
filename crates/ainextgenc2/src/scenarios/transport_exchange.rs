//! MIP4-IES transport scenario: publish radar detections and query via exchange broker.

use mim_transport::{
    ExchangeBroker, GetByFilterRequest, GetByOidRequest, TransportError, TransportResult,
};
use serde::{Deserialize, Serialize};

use crate::scenarios::air_defense_radar::AirDefenseRadarScenario;
use crate::MimStack;

/// Result of publishing and querying via the MIP4-IES transport layer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportScenarioOutput {
    pub published_count: usize,
    pub target_count: usize,
    pub hostile_track: Option<String>,
    pub exchange_json: String,
}

/// Publishes air defense radar detections through a MIP4-IES exchange broker.
#[derive(Clone, Debug)]
pub struct TransportExchangeScenario;

impl TransportExchangeScenario {
    pub fn demo() -> Self {
        Self
    }

    pub fn run(&self, stack: &MimStack) -> TransportResult<TransportScenarioOutput> {
        let registry = stack.registry();
        let store = AirDefenseRadarScenario::demo()
            .build_store(registry)
            .map_err(TransportError::from)?;

        let mut broker = ExchangeBroker::new(registry.clone());
        let responses = broker.publish_store(store.instances().cloned())?;
        let published_count = responses.len();

        let targets = broker.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            property_name: None,
            property_value: None,
        })?;
        let target_count = targets.count;

        let hostile = broker.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            property_name: Some("nameText".into()),
            property_value: Some("HOSTILE-1".into()),
        })?;

        let hostile_track = hostile
            .instances
            .first()
            .map(|instance| instance.oid.to_string());

        if let Some(oid) = &hostile_track {
            let _ = broker.get_by_oid(GetByOidRequest {
                oid: mim_runtime::ObjectIdentifier::new(oid)?,
            })?;
        }

        let exchange_json = broker.serialize_active_store()?;

        Ok(TransportScenarioOutput {
            published_count,
            target_count,
            hostile_track,
            exchange_json,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn transport_scenario_publishes_radar_store() {
        let stack = MimStack::load().expect("stack");
        let output = TransportExchangeScenario::demo().run(&stack).expect("run");
        assert_eq!(output.published_count, 5);
        assert_eq!(output.target_count, 2);
        assert!(output.hostile_track.is_some());
        assert!(output.exchange_json.contains("HOSTILE-1"));
    }
}
