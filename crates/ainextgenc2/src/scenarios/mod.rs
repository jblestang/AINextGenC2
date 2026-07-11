//! Operational scenarios built on the MIM stack.

pub mod air_defense_radar;
pub mod allied_sensor_retrieval;
pub mod dcs_cross_domain;
pub mod sitac_simulator;
pub mod transport_exchange;

pub use air_defense_radar::{AirDefenseRadarScenario, RadarDetection, ScenarioOutput};
pub use allied_sensor_retrieval::{
    AlliedSensorRetrievalOutput, AlliedSensorRetrievalScenario, RetrievedTrack,
};
pub use dcs_cross_domain::{DcsCrossDomainScenario, DcsScenarioOutput};
pub use sitac_simulator::{
    RadarRole, SitacFcs, SitacRadar, SitacSimulatorOutput, SitacSimulatorScenario,
    SitacTrackSummary,
};
pub use transport_exchange::{TransportExchangeScenario, TransportScenarioOutput};
