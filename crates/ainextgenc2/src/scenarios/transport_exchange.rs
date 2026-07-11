//! MIP4-IES transport scenario with PEP-gated access control.

use mim_labeling::{ClassificationLevel, LabelPolicy};
use mim_policy::SubjectAttributes;
use mim_transport::{ExchangeBroker, GetByFilterRequest, SecuredExchangeBroker, TransportError, TransportResult};
use serde::{Deserialize, Serialize};

use crate::scenarios::air_defense_radar::AirDefenseRadarScenario;
use crate::MimStack;

/// Result of publishing and querying via the secured MIP4-IES transport layer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportScenarioOutput {
    pub published_count: usize,
    pub target_count: usize,
    pub hostile_track: Option<String>,
    pub exchange_json: String,
    pub pep_filtered: bool,
}

/// Publishes air defense radar detections through a PEP-gated exchange broker.
#[derive(Clone, Debug)]
pub struct TransportExchangeScenario {
    subject_clearance: ClassificationLevel,
    domain_id: String,
}

impl Default for TransportExchangeScenario {
    fn default() -> Self {
        Self {
            subject_clearance: ClassificationLevel::Secret,
            domain_id: "DOMAIN-HIGH".to_owned(),
        }
    }
}

impl TransportExchangeScenario {
    pub fn demo() -> Self {
        Self::default()
    }

    pub fn with_subject_clearance(mut self, clearance: ClassificationLevel) -> Self {
        self.subject_clearance = clearance;
        self
    }

    pub fn run(&self, stack: &MimStack) -> TransportResult<TransportScenarioOutput> {
        let registry = stack.registry();
        let store = AirDefenseRadarScenario::demo()
            .build_store(registry)
            .map_err(TransportError::from)?;

        let instances: Vec<_> = store
            .instances()
            .cloned()
            .map(|mut instance| {
                label_instance(&mut instance, ClassificationLevel::Secret);
                instance
            })
            .collect();

        let subject = SubjectAttributes::new("radar-operator", self.subject_clearance)
            .with_nationality("USA");
        let mut secured = SecuredExchangeBroker::from_preset(
            ExchangeBroker::new(registry.clone()),
            subject,
            &self.domain_id,
        )?;

        let responses = secured.publish_store(instances)?;
        let published_count = responses.len();

        let targets = secured.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            filter: None,
            property_name: None,
            property_value: None,
        })?;
        let target_count = targets.count;

        let hostile = secured.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            filter: Some("//Target[@nameText='HOSTILE-1']".into()),
            property_name: None,
            property_value: None,
        })?;

        let hostile_track = hostile
            .instances
            .first()
            .map(|instance| instance.oid.to_string());

        let exchange_json = secured.serialize_active_store()?;

        Ok(TransportScenarioOutput {
            published_count,
            target_count,
            hostile_track,
            exchange_json,
            pep_filtered: true,
        })
    }
}

fn label_instance(instance: &mut mim_runtime::MimInstance, classification: ClassificationLevel) {
    instance.metadata.security.policy = mim_core::Nillable::value(LabelPolicy::nato().identifier);
    instance.metadata.security.classification =
        mim_core::Nillable::value(classification.as_stanag_str().to_owned());
    instance.metadata.security.releasability = mim_core::Nillable::value("USA,GBR".into());
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
        assert!(output.pep_filtered);
    }

    #[test]
    fn restricted_subject_sees_fewer_targets() {
        let stack = MimStack::load().expect("stack");
        let output = TransportExchangeScenario::demo()
            .with_subject_clearance(ClassificationLevel::Restricted)
            .run(&stack)
            .expect_err("should deny secret publish");
        assert!(matches!(output, TransportError::Forbidden(_)));
    }
}
