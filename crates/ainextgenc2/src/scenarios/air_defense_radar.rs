//! Air defense radar scenario producing target/track detections.
//!
//! Models a `SiteAirDefenceRadar` sensor that reports `TrackIdentifier` and
//! `Target` instances for each detection, linked via MIM associations.

use mim_core::{MimError, MimResult, SemanticId};
use mim_model::{Metadata, ModelRegistry};
use mim_runtime::{
    InstanceStore, MimInstance, PropertyValue, SerializationFormat, Serializer, Validator,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::MimStack;

/// A single radar track detection with linked target.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RadarDetection {
    pub track_number: u32,
    pub call_sign: String,
    pub latitude: f64,
    pub longitude: f64,
    pub altitude_metres: f64,
    pub speed_knots: f64,
    pub heading_degrees: f64,
    pub iff_mode: String,
}

/// Output of the air defense radar scenario.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScenarioOutput {
    pub radar_name: String,
    pub detections: Vec<RadarDetection>,
    pub validation: ValidationSummary,
    pub exchange_json: String,
}

/// Validation summary for scenario output.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationSummary {
    pub is_valid: bool,
    pub error_count: usize,
}

/// Builds and runs an air defense radar detection scenario.
#[derive(Clone, Debug)]
pub struct AirDefenseRadarScenario {
    radar_name: String,
    detections: Vec<RadarDetection>,
}

impl Default for AirDefenseRadarScenario {
    fn default() -> Self {
        Self {
            radar_name: "Patriot-01".to_owned(),
            detections: vec![
                RadarDetection {
                    track_number: 101,
                    call_sign: "HOSTILE-1".to_owned(),
                    latitude: 50.1109,
                    longitude: 8.6821,
                    altitude_metres: 10_500.0,
                    speed_knots: 480.0,
                    heading_degrees: 135.0,
                    iff_mode: "Mode3/A".to_owned(),
                },
                RadarDetection {
                    track_number: 102,
                    call_sign: "UNKNOWN-2".to_owned(),
                    latitude: 50.2154,
                    longitude: 8.5214,
                    altitude_metres: 8_200.0,
                    speed_knots: 390.0,
                    heading_degrees: 210.0,
                    iff_mode: "NoIFF".to_owned(),
                },
            ],
        }
    }
}

impl AirDefenseRadarScenario {
    pub fn new(radar_name: impl Into<String>) -> Self {
        Self {
            radar_name: radar_name.into(),
            detections: Vec::new(),
        }
    }

    pub fn with_detection(mut self, detection: RadarDetection) -> Self {
        self.detections.push(detection);
        self
    }

    /// Demo scenario with two air tracks.
    pub fn demo() -> Self {
        Self::default()
    }

    pub fn radar_name(&self) -> &str {
        &self.radar_name
    }

    /// Build MIM instances for the radar and its track/target detections.
    pub fn build_store(&self, registry: &ModelRegistry) -> MimResult<InstanceStore> {
        let mut store = InstanceStore::default();
        let mut track_oids = Vec::new();

        let radar = self.build_radar(registry)?;
        let radar_oid = radar.oid.clone();
        store.insert(radar);

        for detection in &self.detections {
            let track = self.build_track(registry, detection)?;
            let track_oid = track.oid.clone();
            track_oids.push(track_oid.clone());
            store.insert(track);

            let mut target = self.build_target(registry, detection)?;
            target.set_association("reportedBy", radar_oid.clone())?;
            target.set_association("trackIdentifier", track_oid)?;
            store.insert(target);
        }

        if let Some(radar) = store.get_mut(&radar_oid) {
            for track_oid in track_oids {
                radar.set_association("producedTrack", track_oid)?;
            }
        }

        Ok(store)
    }

    /// Run the scenario against a loaded stack: build, validate, serialize.
    pub fn run(&self, stack: &MimStack) -> MimResult<ScenarioOutput> {
        let registry = stack.registry();
        let store = self.build_store(registry)?;

        let validator = Validator::new(registry);
        let validation = validator.validate_store(&store);

        let serializer = Serializer::new(registry.clone());
        let exchange_json = serializer.serialize_store(&store, SerializationFormat::Json)?;

        Ok(ScenarioOutput {
            radar_name: self.radar_name.clone(),
            detections: self.detections.clone(),
            validation: ValidationSummary {
                is_valid: validation.is_valid(),
                error_count: validation.error_count(),
            },
            exchange_json,
        })
    }

    fn build_radar(&self, registry: &ModelRegistry) -> MimResult<MimInstance> {
        let class_id = class_semantic_id(registry, "SiteAirDefenceRadar")?;
        let mut metadata = Metadata::default();
        metadata.reporter.name = mim_core::Nillable::value(self.radar_name.clone());

        let mut radar = MimInstance::new("SiteAirDefenceRadar", class_id)?;
        radar.metadata = metadata;
        Ok(radar
            .with_property(PropertyValue::string("nameText", &self.radar_name))
            .with_property(PropertyValue::string("sensorTypeCode", "AirDefenceRadar"))
            .with_property(PropertyValue::string(
                "operationalStatusCode",
                "Active",
            ))
            .with_property(PropertyValue::number("maxRangeDimension", 160.0)))
    }

    fn build_track(
        &self,
        registry: &ModelRegistry,
        detection: &RadarDetection,
    ) -> MimResult<MimInstance> {
        let class_id = class_semantic_id(registry, "TrackIdentifier")?;
        Ok(MimInstance::new("TrackIdentifier", class_id)?
            .with_property(PropertyValue::number(
                "trackNumberQuantity",
                f64::from(detection.track_number),
            ))
            .with_property(PropertyValue::string("trackQualityCode", "Confirmed"))
            .with_property(PropertyValue::json(
                "updateDateTime",
                json!(format_detection_time(detection.track_number)),
            )))
    }

    fn build_target(
        &self,
        registry: &ModelRegistry,
        detection: &RadarDetection,
    ) -> MimResult<MimInstance> {
        let class_id = class_semantic_id(registry, "Target")?;
        Ok(MimInstance::new("Target", class_id)?
            .with_property(PropertyValue::string("nameText", &detection.call_sign))
            .with_property(PropertyValue::string("iffModeCode", &detection.iff_mode))
            .with_property(PropertyValue::json(
                "position",
                json!({
                    "latitude": detection.latitude,
                    "longitude": detection.longitude,
                    "altitudeMetres": detection.altitude_metres,
                }),
            ))
            .with_property(PropertyValue::json(
                "kinematics",
                json!({
                    "speedKnots": detection.speed_knots,
                    "headingDegrees": detection.heading_degrees,
                }),
            )))
    }
}

fn class_semantic_id(registry: &ModelRegistry, class_name: &str) -> MimResult<SemanticId> {
    if let Some(element) = registry.element_by_name(class_name) {
        return Ok(element.semantic_id);
    }
    if let Some(node) = registry.taxonomy_node(class_name) {
        return Ok(node.semantic_id);
    }
    Err(MimError::NotFound(format!(
        "MIM class '{class_name}' not in registry"
    )))
}

fn format_detection_time(track_number: u32) -> String {
    let seconds = track_number % 60;
    format!("2026-07-11T06:15:{seconds:02}Z")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::MimStack;

    #[test]
    fn demo_radar_produces_tracks_and_targets() {
        let stack = MimStack::load().expect("stack");
        let output = AirDefenseRadarScenario::demo().run(&stack).expect("run");

        assert_eq!(output.radar_name, "Patriot-01");
        assert_eq!(output.detections.len(), 2);
        assert!(output.validation.is_valid);
        assert!(output.exchange_json.contains("SiteAirDefenceRadar"));
        assert!(output.exchange_json.contains("TrackIdentifier"));
        assert!(output.exchange_json.contains("Target"));
        assert!(output.exchange_json.contains("HOSTILE-1"));
    }

    #[test]
    fn store_contains_radar_plus_two_tracks_and_targets() {
        let stack = MimStack::load().expect("stack");
        let store = AirDefenseRadarScenario::demo()
            .build_store(stack.registry())
            .expect("store");

        // 1 radar + 2 tracks + 2 targets
        assert_eq!(store.len(), 5);
    }
}
