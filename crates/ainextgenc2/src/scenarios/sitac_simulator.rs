//! SITAC (situational awareness) simulator — multi-radar IADS feed to national C2.
//!
//! Models a national integrated air defence picture with:
//! - 4 radars: airborne AEW, long-range surveillance, FCS weapon-tracking radar, site acquisition
//! - 1 fire-control system (`FireControl`) with the weapon-tracking radar and 4 TEL launchers
//! - National C2 ingest of all sensor and equipment data
//! - Coalition release limited to long-range surveillance tracks only
//! - Airborne (AWACS) platform position refreshed on each simulation step

use mim_core::{MimError, MimResult, SemanticId};
use mim_labeling::{ClassificationLevel, LabelPolicy};
use mim_model::{Metadata, ModelRegistry};
use mim_policy::SubjectAttributes;
use mim_runtime::{
    InstanceStore, MimInstance, PropertyValue, SerializationFormat, Serializer,
};
use mim_transport::{
    ExchangeBroker, GetByFilterRequest, PutObjectRequest, ReplicationAgent, SecuredExchangeBroker,
    TransportError, TransportResult,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::scenarios::air_defense_radar::RadarDetection;
use crate::MimStack;

/// Role of a radar in the SITAC picture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RadarRole {
    Airborne,
    LongRange,
    FcsWeapon,
    SiteAcquisition,
}

/// Geographic position and kinematics for a mobile sensor platform (e.g. AWACS).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SensorPosition {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude_metres: f64,
    pub speed_knots: f64,
    pub heading_degrees: f64,
}

/// One AWACS position refresh published to national C2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AirbornePositionUpdate {
    pub radar_name: String,
    pub step: u32,
    pub timestamp: String,
    pub latitude: f64,
    pub longitude: f64,
    pub altitude_metres: f64,
    pub speed_knots: f64,
    pub heading_degrees: f64,
}

/// Configuration for one simulated radar sensor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SitacRadar {
    pub name: String,
    pub role: RadarRole,
    pub sensor_type_code: String,
    pub max_range_km: f64,
    pub detections: Vec<RadarDetection>,
    pub coalition_shareable: bool,
    /// Present for moving platforms (AWACS); position is refreshed each simulation step.
    pub mobile_platform: Option<SensorPosition>,
}

/// Fire-control system with embedded weapon-tracking radar and TEL battery.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SitacFcs {
    pub name: String,
    pub weapon_radar: SitacRadar,
    pub tel_names: Vec<String>,
}

/// Summary of one published or retrieved track/target.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SitacTrackSummary {
    pub class_name: String,
    pub oid: String,
    pub label: String,
    pub name: Option<String>,
    pub source_radar: Option<String>,
    pub coalition_visible: bool,
}

/// Output of the SITAC simulator scenario.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SitacSimulatorOutput {
    pub national_c2_domain: String,
    pub allied_c2_domain: String,
    pub radar_count: usize,
    pub tel_count: usize,
    pub national_published_count: usize,
    pub replication_applied: usize,
    pub national_target_count: usize,
    pub allied_target_count: usize,
    pub allied_track_count: usize,
    pub long_range_shared_count: usize,
    pub national_only_hidden_from_allied: bool,
    pub exchange_json: String,
    pub radars: Vec<String>,
    pub tels: Vec<String>,
    pub national_targets: Vec<SitacTrackSummary>,
    pub allied_targets: Vec<SitacTrackSummary>,
    pub airborne_position_updates: Vec<AirbornePositionUpdate>,
    pub position_refresh_steps: u32,
    pub position_refresh_interval_seconds: u64,
}

/// Multi-radar SITAC simulator publishing to national C2 with selective coalition sharing.
#[derive(Clone, Debug)]
pub struct SitacSimulatorScenario {
    national_domain_id: String,
    allied_domain_id: String,
    radars: Vec<SitacRadar>,
    fcs: SitacFcs,
    position_refresh_steps: u32,
    position_refresh_interval_seconds: u64,
}

impl Default for SitacSimulatorScenario {
    fn default() -> Self {
        Self::demo_config()
    }
}

impl SitacSimulatorScenario {
    pub fn demo() -> Self {
        Self::default()
    }

    fn demo_config() -> Self {
        let fcs_weapon_radar = SitacRadar {
            name: "FCS-TRACK-RADAR".to_owned(),
            role: RadarRole::FcsWeapon,
            sensor_type_code: "TargetAcquisitionRadar".to_owned(),
            max_range_km: 120.0,
            mobile_platform: None,
            detections: vec![RadarDetection {
                track_number: 401,
                call_sign: "FCS-ENGAGE-1".to_owned(),
                latitude: 50.18,
                longitude: 8.62,
                altitude_metres: 9_800.0,
                speed_knots: 520.0,
                heading_degrees: 175.0,
                iff_mode: "Mode4".to_owned(),
            }],
            coalition_shareable: false,
        };

        Self {
            national_domain_id: "DOMAIN-HIGH".to_owned(),
            allied_domain_id: "DOMAIN-HIGH".to_owned(),
            position_refresh_steps: 3,
            position_refresh_interval_seconds: 60,
            radars: vec![
                SitacRadar {
                    name: "AWACS-01".to_owned(),
                    role: RadarRole::Airborne,
                    sensor_type_code: "AirborneEarlyWarning".to_owned(),
                    max_range_km: 400.0,
                    mobile_platform: Some(SensorPosition {
                        latitude: 50.42,
                        longitude: 8.95,
                        altitude_metres: 9_100.0,
                        speed_knots: 420.0,
                        heading_degrees: 270.0,
                    }),
                    detections: vec![RadarDetection {
                        track_number: 201,
                        call_sign: "AEW-CONTACT-1".to_owned(),
                        latitude: 50.42,
                        longitude: 8.95,
                        altitude_metres: 9_100.0,
                        speed_knots: 430.0,
                        heading_degrees: 270.0,
                        iff_mode: "Mode3/A".to_owned(),
                    }],
                    coalition_shareable: false,
                },
                SitacRadar {
                    name: "LR-SURVEILLANCE-01".to_owned(),
                    role: RadarRole::LongRange,
                    sensor_type_code: "SurveillanceLongRange".to_owned(),
                    max_range_km: 450.0,
                    mobile_platform: None,
                    detections: vec![
                        RadarDetection {
                            track_number: 301,
                            call_sign: "LR-HOSTILE-1".to_owned(),
                            latitude: 50.25,
                            longitude: 8.71,
                            altitude_metres: 11_200.0,
                            speed_knots: 490.0,
                            heading_degrees: 145.0,
                            iff_mode: "NoIFF".to_owned(),
                        },
                        RadarDetection {
                            track_number: 302,
                            call_sign: "LR-UNKNOWN-2".to_owned(),
                            latitude: 50.31,
                            longitude: 8.58,
                            altitude_metres: 7_600.0,
                            speed_knots: 360.0,
                            heading_degrees: 310.0,
                            iff_mode: "Mode3/A".to_owned(),
                        },
                    ],
                    coalition_shareable: true,
                },
                SitacRadar {
                    name: "SITE-ACQ-01".to_owned(),
                    role: RadarRole::SiteAcquisition,
                    sensor_type_code: "SiteGroundSurveillance".to_owned(),
                    max_range_km: 80.0,
                    mobile_platform: None,
                    detections: vec![RadarDetection {
                        track_number: 501,
                        call_sign: "ACQ-LOCAL-1".to_owned(),
                        latitude: 50.12,
                        longitude: 8.55,
                        altitude_metres: 4_200.0,
                        speed_knots: 280.0,
                        heading_degrees: 95.0,
                        iff_mode: "Mode2".to_owned(),
                    }],
                    coalition_shareable: false,
                },
            ],
            fcs: SitacFcs {
                name: "FCS-BATTERY-01".to_owned(),
                weapon_radar: fcs_weapon_radar,
                tel_names: vec![
                    "TEL-01".to_owned(),
                    "TEL-02".to_owned(),
                    "TEL-03".to_owned(),
                    "TEL-04".to_owned(),
                ],
            },
        }
    }

    /// Build the full SITAC instance store (radars, tracks, FCS, TELs).
    pub fn build_store(&self, registry: &ModelRegistry) -> MimResult<InstanceStore> {
        let mut store = InstanceStore::default();

        for radar in &self.radars {
            append_radar_store(registry, &mut store, radar)?;
        }

        append_fcs_store(registry, &mut store, &self.fcs)?;

        Ok(store)
    }

    /// Run ingest to national C2 and coalition replication with selective sharing.
    pub fn run(&self, stack: &MimStack) -> TransportResult<SitacSimulatorOutput> {
        let registry = stack.registry();
        let mut store = self.build_store(registry).map_err(TransportError::from)?;
        let mut mobile_positions = initial_mobile_positions(self, &store);

        let shareable_track_numbers = shareable_track_numbers(self);
        let instances: Vec<_> = store
            .instances()
            .cloned()
            .map(|mut instance| {
                let coalition = is_coalition_releasable(&instance, &shareable_track_numbers);
                label_instance(&mut instance, ClassificationLevel::Secret, coalition);
                instance
            })
            .collect();

        let national_subject = SubjectAttributes::new("national-sitac-operator", ClassificationLevel::Secret)
            .with_nationality("USA");
        let mut national_c2 = SecuredExchangeBroker::from_preset(
            ExchangeBroker::new(registry.clone()),
            national_subject,
            &self.national_domain_id,
        )?;
        let national_responses = national_c2.publish_store(instances)?;
        let mut national_published_count = national_responses.len();

        let mut airborne_position_updates = initial_airborne_position_updates(self, &store);

        for step in 1..=self.position_refresh_steps {
            let refreshed = refresh_mobile_radar_positions(
                self,
                &mut store,
                &mut mobile_positions,
                step,
                self.position_refresh_interval_seconds,
            )?;
            if refreshed.is_empty() {
                continue;
            }
            for instance in refreshed {
                let mut labeled = instance;
                let coalition =
                    is_coalition_releasable(&labeled, &shareable_track_numbers);
                label_instance(&mut labeled, ClassificationLevel::Secret, coalition);
                national_c2.put_object(PutObjectRequest { instance: labeled })?;
                national_published_count += 1;
            }
            airborne_position_updates.extend(refreshed_position_updates(
                self,
                &store,
                step,
                self.position_refresh_interval_seconds,
            ));
        }

        let mut allied_broker = ExchangeBroker::new(registry.clone());
        let replication = ReplicationAgent::pull_and_apply(&mut allied_broker, national_c2.broker(), 0)?;

        let allied_subject = SubjectAttributes::new("allied-sitac-analyst", ClassificationLevel::Secret)
            .with_nationality("GBR");
        let allied_c2 = SecuredExchangeBroker::from_preset(
            allied_broker,
            allied_subject,
            &self.allied_domain_id,
        )?;

        let national_targets = national_c2.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            filter: None,
            property_name: None,
            property_value: None,
            limit: None,
            offset: None,
        })?;

        let allied_targets = allied_c2.get_by_filter(GetByFilterRequest {
            class_name: "Target".into(),
            filter: None,
            property_name: None,
            property_value: None,
            limit: None,
            offset: None,
        })?;

        let allied_tracks = allied_c2.get_by_filter(GetByFilterRequest {
            class_name: "TrackIdentifier".into(),
            filter: None,
            property_name: None,
            property_value: None,
            limit: None,
            offset: None,
        })?;

        let national_only_hidden = national_targets.count > allied_targets.count;
        let long_range_shared_count = allied_targets
            .instances
            .iter()
            .filter(|instance| {
                instance
                    .property("nameText")
                    .and_then(|p| p.value.as_option())
                    .and_then(|v| v.as_str())
                    .is_some_and(|name| name.starts_with("LR-"))
            })
            .count();

        let serializer = Serializer::new(registry.clone());
        let exchange_json = serializer
            .serialize_store(&store, SerializationFormat::Json)
            .map_err(TransportError::from)?;

        let national_target_summaries = summarize_targets(&national_targets.instances, self, true)?;
        let allied_target_summaries = summarize_targets(&allied_targets.instances, self, false)?;

        let mut radars: Vec<String> = self.radars.iter().map(|r| r.name.clone()).collect();
        radars.push(self.fcs.weapon_radar.name.clone());

        Ok(SitacSimulatorOutput {
            national_c2_domain: self.national_domain_id.clone(),
            allied_c2_domain: self.allied_domain_id.clone(),
            radar_count: radars.len(),
            tel_count: self.fcs.tel_names.len(),
            national_published_count,
            replication_applied: replication.applied,
            national_target_count: national_targets.count,
            allied_target_count: allied_targets.count,
            allied_track_count: allied_tracks.count,
            long_range_shared_count,
            national_only_hidden_from_allied: national_only_hidden,
            exchange_json,
            radars,
            tels: self.fcs.tel_names.clone(),
            national_targets: national_target_summaries,
            allied_targets: allied_target_summaries,
            airborne_position_updates,
            position_refresh_steps: self.position_refresh_steps,
            position_refresh_interval_seconds: self.position_refresh_interval_seconds,
        })
    }
}

fn shareable_track_numbers(scenario: &SitacSimulatorScenario) -> Vec<u32> {
    let mut numbers = Vec::new();
    for radar in &scenario.radars {
        if radar.coalition_shareable {
            for detection in &radar.detections {
                numbers.push(detection.track_number);
            }
        }
    }
    numbers
}

fn append_radar_store(
    registry: &ModelRegistry,
    store: &mut InstanceStore,
    radar: &SitacRadar,
) -> MimResult<()> {
    let mut track_oids = Vec::new();
    let sensor = build_radar(registry, radar)?;
    let sensor_oid = sensor.oid.clone();
    store.insert(sensor);

    for detection in &radar.detections {
        let track = build_track(registry, detection)?;
        let track_oid = track.oid.clone();
        track_oids.push(track_oid.clone());
        store.insert(track);

        let mut target = build_target(registry, detection)?;
        target.set_association("reportedBy", sensor_oid.clone())?;
        target.set_association("trackIdentifier", track_oid)?;
        store.insert(target);
    }

    if let Some(sensor) = store.get_mut(&sensor_oid) {
        for track_oid in track_oids {
            sensor.set_association("producedTrack", track_oid)?;
        }
    }

    Ok(())
}

fn append_fcs_store(
    registry: &ModelRegistry,
    store: &mut InstanceStore,
    fcs: &SitacFcs,
) -> MimResult<()> {
    let fcs_instance = build_fcs(registry, fcs)?;
    let fcs_oid = fcs_instance.oid.clone();
    store.insert(fcs_instance);

    let mut weapon_track_oids = Vec::new();
    let weapon_radar = build_radar(registry, &fcs.weapon_radar)?;
    let weapon_radar_oid = weapon_radar.oid.clone();
    store.insert(weapon_radar);

    if let Some(fcs_node) = store.get_mut(&fcs_oid) {
        fcs_node.set_association("equipment", weapon_radar_oid.clone())?;
    }
    if let Some(radar) = store.get_mut(&weapon_radar_oid) {
        radar.set_association("parentOrganisation", fcs_oid.clone())?;
    }

    for detection in &fcs.weapon_radar.detections {
        let track = build_track(registry, detection)?;
        let track_oid = track.oid.clone();
        weapon_track_oids.push(track_oid.clone());
        store.insert(track);

        let mut target = build_target(registry, detection)?;
        target.set_association("reportedBy", weapon_radar_oid.clone())?;
        target.set_association("trackIdentifier", track_oid)?;
        store.insert(target);
    }

    if let Some(radar) = store.get_mut(&weapon_radar_oid) {
        for track_oid in weapon_track_oids {
            radar.set_association("producedTrack", track_oid)?;
        }
    }

    for tel_name in &fcs.tel_names {
        let tel = build_tel(registry, tel_name)?;
        let tel_oid = tel.oid.clone();
        store.insert(tel);

        if let Some(fcs_node) = store.get_mut(&fcs_oid) {
            fcs_node.set_association("equipment", tel_oid.clone())?;
        }
        if let Some(tel_instance) = store.get_mut(&tel_oid) {
            tel_instance.set_association("parentOrganisation", fcs_oid.clone())?;
        }
    }

    Ok(())
}

fn build_radar(registry: &ModelRegistry, radar: &SitacRadar) -> MimResult<MimInstance> {
    let class_name = radar_class_name(radar.role);
    let class_id = class_semantic_id(registry, class_name)?;
    let mut metadata = Metadata::default();
    metadata.reporter.name = mim_core::Nillable::value(radar.name.clone());

    let mut instance = MimInstance::new(class_name, class_id)?
        .with_property(PropertyValue::string("nameText", &radar.name))
        .with_property(PropertyValue::string("sensorTypeCode", &radar.sensor_type_code))
        .with_property(PropertyValue::string("operationalStatusCode", "Active"))
        .with_property(PropertyValue::number("maxRangeDimension", radar.max_range_km))
        .with_property(PropertyValue::string(
            "roleCode",
            &format!("{:?}", radar.role),
        ))
        .with_metadata(metadata);

    if let Some(position) = radar.mobile_platform {
        instance = apply_sensor_position(instance, position, 0);
    }

    Ok(instance)
}

fn apply_sensor_position(
    mut instance: MimInstance,
    position: SensorPosition,
    step: u32,
) -> MimInstance {
    upsert_property(
        &mut instance,
        PropertyValue::json(
            "position",
            json!({
                "latitude": position.latitude,
                "longitude": position.longitude,
                "altitudeMetres": position.altitude_metres,
            }),
        ),
    );
    upsert_property(
        &mut instance,
        PropertyValue::json(
            "kinematics",
            json!({
                "speedKnots": position.speed_knots,
                "headingDegrees": position.heading_degrees,
            }),
        ),
    );
    upsert_property(
        &mut instance,
        PropertyValue::json(
            "positionUpdateDateTime",
            json!(format_position_timestamp(step)),
        ),
    );
    instance
}

fn upsert_property(instance: &mut MimInstance, property: PropertyValue) {
    if let Some(existing) = instance
        .properties
        .iter_mut()
        .find(|p| p.name == property.name)
    {
        *existing = property;
    } else {
        instance.properties.push(property);
    }
}

fn advance_position(position: SensorPosition, elapsed_seconds: f64) -> SensorPosition {
    let distance_nm = position.speed_knots * elapsed_seconds / 3600.0;
    let heading_rad = position.heading_degrees.to_radians();
    let lat_delta = distance_nm * heading_rad.cos() / 60.0;
    let lon_scale = position.latitude.to_radians().cos().max(0.01);
    let lon_delta = distance_nm * heading_rad.sin() / (60.0 * lon_scale);

    SensorPosition {
        latitude: position.latitude + lat_delta,
        longitude: position.longitude + lon_delta,
        ..position
    }
}

fn initial_mobile_positions(
    scenario: &SitacSimulatorScenario,
    store: &InstanceStore,
) -> Vec<(String, mim_runtime::oid::ObjectIdentifier, SensorPosition)> {
    scenario
        .radars
        .iter()
        .filter_map(|radar| {
            let position = radar.mobile_platform?;
            let oid = store
                .instances()
                .find(|instance| radar_instance_name(instance) == Some(radar.name.as_str()))?
                .oid
                .clone();
            Some((radar.name.clone(), oid, position))
        })
        .collect()
}

fn initial_airborne_position_updates(
    scenario: &SitacSimulatorScenario,
    _store: &InstanceStore,
) -> Vec<AirbornePositionUpdate> {
    scenario
        .radars
        .iter()
        .filter_map(|radar| {
            let position = radar.mobile_platform?;
            Some(AirbornePositionUpdate {
                radar_name: radar.name.clone(),
                step: 0,
                timestamp: format_position_timestamp(0),
                latitude: position.latitude,
                longitude: position.longitude,
                altitude_metres: position.altitude_metres,
                speed_knots: position.speed_knots,
                heading_degrees: position.heading_degrees,
            })
        })
        .collect()
}

fn refresh_mobile_radar_positions(
    scenario: &SitacSimulatorScenario,
    store: &mut InstanceStore,
    mobile_positions: &mut [(String, mim_runtime::oid::ObjectIdentifier, SensorPosition)],
    step: u32,
    interval_seconds: u64,
) -> TransportResult<Vec<MimInstance>> {
    let mut refreshed = Vec::new();
    for (name, oid, position) in mobile_positions.iter_mut() {
        let radar = scenario
            .radars
            .iter()
            .find(|r| r.name == *name)
            .ok_or_else(|| {
                TransportError::Validation(format!("mobile radar '{name}' not in scenario"))
            })?;
        if radar.mobile_platform.is_none() {
            continue;
        }

        *position = advance_position(*position, interval_seconds as f64);
        let instance = store.get_mut(oid).ok_or_else(|| {
            TransportError::Validation(format!("radar instance '{name}' missing from store"))
        })?;
        *instance = apply_sensor_position(instance.clone(), *position, step);
        refreshed.push(instance.clone());
    }
    Ok(refreshed)
}

fn refreshed_position_updates(
    scenario: &SitacSimulatorScenario,
    store: &InstanceStore,
    step: u32,
    interval_seconds: u64,
) -> Vec<AirbornePositionUpdate> {
    scenario
        .radars
        .iter()
        .filter_map(|radar| {
            let _ = radar.mobile_platform?;
            let instance = store.instances().find(|i| {
                radar_instance_name(i) == Some(radar.name.as_str())
            })?;
            let position = read_sensor_position(instance)?;
            Some(AirbornePositionUpdate {
                radar_name: radar.name.clone(),
                step,
                timestamp: format_position_timestamp(step * interval_seconds as u32),
                latitude: position.latitude,
                longitude: position.longitude,
                altitude_metres: position.altitude_metres,
                speed_knots: position.speed_knots,
                heading_degrees: position.heading_degrees,
            })
        })
        .collect()
}

fn radar_instance_name(instance: &MimInstance) -> Option<&str> {
    instance
        .property("nameText")
        .and_then(|p| p.value.as_option())
        .and_then(|v| v.as_str())
}

fn read_sensor_position(instance: &MimInstance) -> Option<SensorPosition> {
    let position = instance.property("position")?.value.as_option()?;
    let kinematics = instance.property("kinematics")?.value.as_option()?;
    Some(SensorPosition {
        latitude: position.get("latitude")?.as_f64()?,
        longitude: position.get("longitude")?.as_f64()?,
        altitude_metres: position.get("altitudeMetres")?.as_f64()?,
        speed_knots: kinematics.get("speedKnots")?.as_f64()?,
        heading_degrees: kinematics.get("headingDegrees")?.as_f64()?,
    })
}

fn format_position_timestamp(step_or_seconds: u32) -> String {
    let minutes = step_or_seconds / 60;
    let seconds = step_or_seconds % 60;
    format!("2026-07-11T14:{minutes:02}:{seconds:02}Z")
}

fn build_fcs(registry: &ModelRegistry, fcs: &SitacFcs) -> MimResult<MimInstance> {
    let class_id = class_semantic_id(registry, "FireControl")?;
    let mut metadata = Metadata::default();
    metadata.reporter.name = mim_core::Nillable::value(fcs.name.clone());

    Ok(MimInstance::new("FireControl", class_id)?
        .with_property(PropertyValue::string("nameText", &fcs.name))
        .with_property(PropertyValue::string("operationalStatusCode", "Active"))
        .with_property(PropertyValue::number(
            "launcherCountQuantity",
            f64::from(fcs.tel_names.len() as u32),
        ))
        .with_metadata(metadata))
}

fn build_tel(registry: &ModelRegistry, name: &str) -> MimResult<MimInstance> {
    let class_id = class_semantic_id(registry, "MissileSystem")?;
    Ok(MimInstance::new("MissileSystem", class_id)?
        .with_property(PropertyValue::string("nameText", name))
        .with_property(PropertyValue::string("operationalStatusCode", "Ready"))
        .with_property(PropertyValue::string("weaponTypeCode", "SurfaceToAirMissile"))
        .with_property(PropertyValue::number("missileCountQuantity", 4.0)))
}

fn build_track(registry: &ModelRegistry, detection: &RadarDetection) -> MimResult<MimInstance> {
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

fn build_target(registry: &ModelRegistry, detection: &RadarDetection) -> MimResult<MimInstance> {
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

fn radar_class_name(role: RadarRole) -> &'static str {
    match role {
        RadarRole::Airborne | RadarRole::LongRange | RadarRole::FcsWeapon => "SiteAirDefenceRadar",
        RadarRole::SiteAcquisition => "SiteGroundSurveillanceRadar",
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
    format!("2026-07-11T14:20:{seconds:02}Z")
}

fn label_instance(
    instance: &mut MimInstance,
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

fn is_coalition_releasable(instance: &MimInstance, shareable_tracks: &[u32]) -> bool {
    match instance.class_name.as_str() {
        "Target" => instance
            .property("nameText")
            .and_then(|p| p.value.as_option())
            .and_then(|v| v.as_str())
            .is_some_and(|name| name.starts_with("LR-")),
        "TrackIdentifier" => instance
            .property("trackNumberQuantity")
            .and_then(|p| p.value.as_option())
            .and_then(|v| v.as_f64())
            .and_then(|n| u32::try_from(n as i64).ok())
            .is_some_and(|track| shareable_tracks.contains(&track)),
        "SiteAirDefenceRadar" | "SiteGroundSurveillanceRadar" => instance
            .property("sensorTypeCode")
            .and_then(|p| p.value.as_option())
            .and_then(|v| v.as_str())
            == Some("SurveillanceLongRange"),
        _ => false,
    }
}

fn summarize_targets(
    instances: &[MimInstance],
    scenario: &SitacSimulatorScenario,
    national_view: bool,
) -> TransportResult<Vec<SitacTrackSummary>> {
    let shareable = shareable_track_numbers(scenario);
    instances
        .iter()
        .map(|instance| {
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
            let coalition_visible = is_coalition_releasable(instance, &shareable);
            Ok(SitacTrackSummary {
                class_name: instance.class_name.clone(),
                oid: instance.oid.to_string(),
                label,
                source_radar: name.as_ref().and_then(|n| source_radar_for_target(n, scenario)),
                name,
                coalition_visible: if national_view {
                    coalition_visible
                } else {
                    coalition_visible
                },
            })
        })
        .collect()
}

fn source_radar_for_target(call_sign: &str, scenario: &SitacSimulatorScenario) -> Option<String> {
    for radar in &scenario.radars {
        if radar
            .detections
            .iter()
            .any(|d| d.call_sign == call_sign)
        {
            return Some(radar.name.clone());
        }
    }
    if scenario
        .fcs
        .weapon_radar
        .detections
        .iter()
        .any(|d| d.call_sign == call_sign)
    {
        return Some(scenario.fcs.weapon_radar.name.clone());
    }
    None
}

trait MimInstanceMetadata {
    fn with_metadata(self, metadata: Metadata) -> Self;
}

impl MimInstanceMetadata for MimInstance {
    fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sitac_store_contains_four_radars_fcs_and_four_tels() {
        let stack = MimStack::load().expect("stack");
        let scenario = SitacSimulatorScenario::demo();
        let store = scenario.build_store(stack.registry()).expect("store");

        let radars = store
            .instances()
            .filter(|i| {
                i.class_name == "SiteAirDefenceRadar"
                    || i.class_name == "SiteGroundSurveillanceRadar"
            })
            .count();
        let fcs = store
            .instances()
            .filter(|i| i.class_name == "FireControl")
            .count();
        let tels = store
            .instances()
            .filter(|i| i.class_name == "MissileSystem")
            .count();
        let targets = store
            .instances()
            .filter(|i| i.class_name == "Target")
            .count();

        assert_eq!(radars, 4);
        assert_eq!(fcs, 1);
        assert_eq!(tels, 4);
        assert_eq!(targets, 5);
    }

    #[test]
    fn sitac_only_shares_long_range_tracks_to_allied_c2() {
        let stack = MimStack::load().expect("stack");
        let output = SitacSimulatorScenario::demo().run(&stack).expect("run");

        assert_eq!(output.radar_count, 4);
        assert_eq!(output.tel_count, 4);
        assert_eq!(output.national_target_count, 5);
        assert_eq!(output.allied_target_count, 2);
        assert_eq!(output.long_range_shared_count, 2);
        assert!(output.national_only_hidden_from_allied);

        assert!(output
            .allied_targets
            .iter()
            .all(|t| t.name.as_deref().is_some_and(|n| n.starts_with("LR-"))));
        assert!(!output.allied_targets.iter().any(|t| {
            matches!(
                t.name.as_deref(),
                Some("AEW-CONTACT-1" | "FCS-ENGAGE-1" | "ACQ-LOCAL-1")
            )
        }));
    }

    #[test]
    fn awacs_has_initial_position_and_refreshes_on_run() {
        let stack = MimStack::load().expect("stack");
        let output = SitacSimulatorScenario::demo().run(&stack).expect("run");

        assert_eq!(output.position_refresh_steps, 3);
        assert_eq!(output.airborne_position_updates.len(), 4);
        assert_eq!(output.airborne_position_updates[0].step, 0);
        assert_eq!(output.airborne_position_updates[0].radar_name, "AWACS-01");

        let initial_lon = output.airborne_position_updates[0].longitude;
        let final_lon = output
            .airborne_position_updates
            .last()
            .expect("final")
            .longitude;
        assert!(
            final_lon < initial_lon,
            "AWACS heading 270° should move west: {initial_lon} -> {final_lon}"
        );
        assert!(output.national_published_count > 19);
    }

    #[test]
    fn advance_position_moves_west_on_heading_270() {
        let start = SensorPosition {
            latitude: 50.42,
            longitude: 8.95,
            altitude_metres: 9_100.0,
            speed_knots: 420.0,
            heading_degrees: 270.0,
        };
        let advanced = advance_position(start, 60.0);
        assert!(advanced.longitude < start.longitude);
        assert!((advanced.latitude - start.latitude).abs() < 0.001);
    }

    #[test]
    fn long_range_radar_marked_coalition_releasable() {
        let stack = MimStack::load().expect("stack");
        let scenario = SitacSimulatorScenario::demo();
        let store = scenario.build_store(stack.registry()).expect("store");
        let shareable = shareable_track_numbers(&scenario);

        let lr_radar = store
            .instances()
            .find(|i| {
                i.property("nameText")
                    .and_then(|p| p.value.as_option())
                    .and_then(|v| v.as_str())
                    == Some("LR-SURVEILLANCE-01")
            })
            .expect("long range radar");

        assert!(is_coalition_releasable(lr_radar, &shareable));
    }
}
