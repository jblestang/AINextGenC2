//! Allied C2 sensor retrieval — national C2 publishes radar tracks; coalition partner retrieves.
//!
//! Models the MIP4-IES flow:
//! 1. A `SiteAirDefenceRadar` sensor reports `TrackIdentifier` and `Target` instances to a USA national C2.
//! 2. The national broker journals PutObject operations with NATO labels and coalition releasability.
//! 3. A GBR allied C2 replicates the journal via [`ReplicationAgent`].
//! 4. A GBR analyst queries targets/tracks through a PEP-gated broker (nationality + clearance).

use mim_labeling::{ClassificationLevel, LabelPolicy};
use mim_policy::SubjectAttributes;
use mim_transport::{
    ExchangeBroker, GetByFilterRequest, ReplicationAgent, SecuredExchangeBroker, TransportError,
    TransportResult,
};
use serde::{Deserialize, Serialize};

use crate::scenarios::air_defense_radar::{AirDefenseRadarScenario, RadarDetection};
use crate::MimStack;

/// A target or track retrieved by the allied C2 analyst.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrievedTrack {
    pub class_name: String,
    pub oid: String,
    pub label: String,
    pub name: Option<String>,
}

/// Output of the allied sensor retrieval scenario.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlliedSensorRetrievalOutput {
    pub sensor_name: String,
    pub usa_nationality: String,
    pub allied_nationality: String,
    pub usa_published_count: usize,
    pub replication_applied: usize,
    pub gbr_target_count: usize,
    pub gbr_track_count: usize,
    pub hostile_track_oid: Option<String>,
    pub usa_only_hidden_from_allied: bool,
    pub retrieved: Vec<RetrievedTrack>,
}

/// National + allied C2 exchange for coalition sensor track sharing.
#[derive(Clone, Debug)]
pub struct AlliedSensorRetrievalScenario {
    usa_domain_id: String,
    allied_domain_id: String,
}

impl Default for AlliedSensorRetrievalScenario {
    fn default() -> Self {
        Self {
            usa_domain_id: "DOMAIN-HIGH".to_owned(),
            allied_domain_id: "DOMAIN-HIGH".to_owned(),
        }
    }
}

impl AlliedSensorRetrievalScenario {
    pub fn demo() -> Self {
        Self::default()
    }

    pub fn run(&self, stack: &MimStack) -> TransportResult<AlliedSensorRetrievalOutput> {
        let registry = stack.registry();
        let sensor = AirDefenseRadarScenario::demo().with_detection(RadarDetection {
            track_number: 103,
            call_sign: "USA-EYES-ONLY".to_owned(),
            latitude: 50.05,
            longitude: 8.75,
            altitude_metres: 12_000.0,
            speed_knots: 510.0,
            heading_degrees: 90.0,
            iff_mode: "Mode4".to_owned(),
        });
        let sensor_name = sensor.radar_name().to_owned();
        let store = sensor.build_store(registry).map_err(TransportError::from)?;

        let instances: Vec<_> = store
            .instances()
            .cloned()
            .map(|mut instance| {
                let coalition = is_coalition_releasable(&instance);
                label_instance(&mut instance, ClassificationLevel::Secret, coalition);
                instance
            })
            .collect();

        let usa_subject = SubjectAttributes::new("usa-sensor-operator", ClassificationLevel::Secret)
            .with_nationality("USA");
        let mut usa_c2 = SecuredExchangeBroker::from_preset(
            ExchangeBroker::new(registry.clone()),
            usa_subject,
            &self.usa_domain_id,
        )?;
        let usa_responses = usa_c2.publish_store(instances)?;
        let usa_published_count = usa_responses.len();

        let mut allied_broker = ExchangeBroker::new(registry.clone());
        let replication = ReplicationAgent::pull_and_apply(
            &mut allied_broker,
            usa_c2.broker(),
            0,
        )?;

        let gbr_subject = SubjectAttributes::new("gbr-allied-analyst", ClassificationLevel::Secret)
            .with_nationality("GBR");
        let gbr_c2 = SecuredExchangeBroker::from_preset(
            allied_broker,
            gbr_subject,
            &self.allied_domain_id,
        )?;

        let targets = gbr_c2.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            filter: None,
            property_name: None,
            property_value: None,
            limit: None,
            offset: None,
        })?;
        let tracks = gbr_c2.get_by_filter(GetByFilterRequest {
            class_name: "TrackIdentifier".into(),
            filter: None,
            property_name: None,
            property_value: None,
            limit: None,
            offset: None,
        })?;

        let hostile = gbr_c2.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            filter: Some("//Target[@nameText='HOSTILE-1']".into()),
            property_name: None,
            property_value: None,
            limit: None,
            offset: None,
        })?;
        let hostile_track_oid = hostile
            .instances
            .first()
            .map(|instance| instance.oid.to_string());

        let usa_only = gbr_c2.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            filter: Some("//Target[@nameText='USA-EYES-ONLY']".into()),
            property_name: None,
            property_value: None,
            limit: None,
            offset: None,
        })?;
        let usa_only_hidden_from_allied = usa_only.instances.is_empty();

        let mut retrieved = Vec::new();
        for instance in targets.instances {
            retrieved.push(track_summary(&instance, "Target")?);
        }
        for instance in tracks.instances {
            retrieved.push(track_summary(&instance, "TrackIdentifier")?);
        }

        Ok(AlliedSensorRetrievalOutput {
            sensor_name,
            usa_nationality: "USA".into(),
            allied_nationality: "GBR".into(),
            usa_published_count,
            replication_applied: replication.applied,
            gbr_target_count: targets.count,
            gbr_track_count: tracks.count,
            hostile_track_oid,
            usa_only_hidden_from_allied,
            retrieved,
        })
    }
}

fn track_summary(
    instance: &mim_runtime::MimInstance,
    class_name: &str,
) -> TransportResult<RetrievedTrack> {
    let label = instance
        .metadata
        .security
        .classification
        .as_option()
        .cloned()
        .unwrap_or_else(|| "UNCLASSIFIED".into());
    let name = instance
        .property("nameText")
        .and_then(|p| p.value.as_option())
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    Ok(RetrievedTrack {
        class_name: class_name.into(),
        oid: instance.oid.to_string(),
        label,
        name,
    })
}

fn label_instance(
    instance: &mut mim_runtime::MimInstance,
    classification: ClassificationLevel,
    coalition_releasable: bool,
) {
    instance.metadata.security.policy = mim_core::Nillable::value(LabelPolicy::nato().identifier);
    instance.metadata.security.classification =
        mim_core::Nillable::value(classification.as_stanag_str().to_owned());
    instance.metadata.security.releasability = mim_core::Nillable::value(if coalition_releasable {
        "USA,GBR".into()
    } else {
        "USA".into()
    });
}

/// Track 103 / `USA-EYES-ONLY` is national-only; radar and other tracks are coalition-releasable.
fn is_coalition_releasable(instance: &mim_runtime::MimInstance) -> bool {
    match instance.class_name.as_str() {
        "Target" => instance
            .property("nameText")
            .and_then(|p| p.value.as_option())
            .and_then(|v| v.as_str())
            != Some("USA-EYES-ONLY"),
        "TrackIdentifier" => instance
            .property("trackNumberQuantity")
            .and_then(|p| p.value.as_option())
            .and_then(|v| v.as_f64())
            != Some(103.0),
        _ => true,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn allied_c2_retrieves_coalition_sensor_tracks() {
        let stack = MimStack::load().expect("stack");
        let output = AlliedSensorRetrievalScenario::demo()
            .run(&stack)
            .expect("run");

        assert_eq!(output.sensor_name, "Patriot-01");
        assert_eq!(output.usa_published_count, 7);
        assert_eq!(output.replication_applied, 7);
        assert_eq!(output.gbr_target_count, 2);
        assert_eq!(output.gbr_track_count, 2);
        assert!(output.hostile_track_oid.is_some());
        assert!(output.usa_only_hidden_from_allied);
        assert!(output
            .retrieved
            .iter()
            .any(|track| track.name.as_deref() == Some("HOSTILE-1")));
        assert!(!output
            .retrieved
            .iter()
            .any(|track| track.name.as_deref() == Some("USA-EYES-ONLY")));
    }

    #[test]
    fn usa_only_subject_sees_all_published_targets() {
        let stack = MimStack::load().expect("stack");
        let registry = stack.registry();
        let sensor = AirDefenseRadarScenario::demo().with_detection(RadarDetection {
            track_number: 103,
            call_sign: "USA-EYES-ONLY".to_owned(),
            latitude: 50.05,
            longitude: 8.75,
            altitude_metres: 12_000.0,
            speed_knots: 510.0,
            heading_degrees: 90.0,
            iff_mode: "Mode4".to_owned(),
        });
        let store = sensor.build_store(registry).expect("store");
        let instances: Vec<_> = store
            .instances()
            .cloned()
            .map(|mut instance| {
                let coalition = is_coalition_releasable(&instance);
                label_instance(&mut instance, ClassificationLevel::Secret, coalition);
                instance
            })
            .collect();

        let usa_subject = SubjectAttributes::new("usa-analyst", ClassificationLevel::Secret)
            .with_nationality("USA");
        let mut usa_c2 = SecuredExchangeBroker::from_preset(
            ExchangeBroker::new(registry.clone()),
            usa_subject,
            "DOMAIN-HIGH",
        )
        .expect("secured");
        usa_c2.publish_store(instances).expect("publish");

        let targets = usa_c2
            .get_by_filter(GetByFilterRequest {
                class_name: "Target".into(),
                filter: None,
                property_name: None,
                property_value: None,
                limit: None,
                offset: None,
            })
            .expect("filter");
        assert_eq!(targets.count, 3);
    }

    #[test]
    fn non_releasable_nationality_sees_no_coalition_targets() {
        let stack = MimStack::load().expect("stack");
        let registry = stack.registry();
        let store = AirDefenseRadarScenario::demo()
            .build_store(registry)
            .expect("store");
        let instances: Vec<_> = store
            .instances()
            .cloned()
            .map(|mut instance| {
                label_instance(&mut instance, ClassificationLevel::Secret, true);
                instance
            })
            .collect();

        let mut usa_c2 = SecuredExchangeBroker::from_preset(
            ExchangeBroker::new(registry.clone()),
            SubjectAttributes::new("usa-sensor-operator", ClassificationLevel::Secret)
                .with_nationality("USA"),
            "DOMAIN-HIGH",
        )
        .expect("secured");
        usa_c2.publish_store(instances).expect("publish");

        let mut allied_broker = ExchangeBroker::new(registry.clone());
        ReplicationAgent::pull_and_apply(&mut allied_broker, usa_c2.broker(), 0).expect("sync");

        let deu_c2 = SecuredExchangeBroker::from_preset(
            allied_broker,
            SubjectAttributes::new("deu-analyst", ClassificationLevel::Secret)
                .with_nationality("DEU"),
            "DOMAIN-HIGH",
        )
        .expect("secured");

        let filtered = deu_c2
            .get_by_filter(GetByFilterRequest {
                class_name: "Target".into(),
                filter: None,
                property_name: None,
                property_value: None,
                limit: None,
                offset: None,
            })
            .expect("filter");
        assert_eq!(filtered.count, 0);
    }
}
