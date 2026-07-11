//! Operational scenarios built on the MIM stack.

pub mod air_defense_radar;
pub mod dcs_cross_domain;
pub mod transport_exchange;

pub use air_defense_radar::{AirDefenseRadarScenario, RadarDetection, ScenarioOutput};
pub use dcs_cross_domain::{DcsCrossDomainScenario, DcsScenarioOutput};
pub use transport_exchange::{TransportExchangeScenario, TransportScenarioOutput};
