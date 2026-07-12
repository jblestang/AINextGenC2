//! Operational scenarios built on the MIM stack.

pub mod air_defense_radar;
pub mod allied_sensor_retrieval;
pub mod dcs_cross_domain;
pub mod transport_exchange;

pub use air_defense_radar::{AirDefenseRadarScenario, RadarDetection, ScenarioOutput};
pub use allied_sensor_retrieval::{
    AlliedSensorRetrievalOutput, AlliedSensorRetrievalScenario, FederationTransport,
    PolicyAccessDecision, RetrievedTrack,
};
pub use dcs_cross_domain::{DcsCrossDomainScenario, DcsScenarioOutput};
pub use transport_exchange::{TransportExchangeScenario, TransportScenarioOutput};
