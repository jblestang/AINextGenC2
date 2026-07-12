//! AINextGenC2 library — next-generation C4 base on MIM.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented
)]

pub mod scenarios;
pub mod stack;

pub use scenarios::{
    AirDefenseRadarScenario, AlliedSensorRetrievalOutput, AlliedSensorRetrievalScenario,
    CoalitionExerciseScenario, CoalitionReplicationMode, DcsCrossDomainScenario, DcsScenarioOutput,
    FederationTransport, PolicyAccessDecision, RadarDetection, RetrievedTrack, ScenarioOutput,
    TransportExchangeScenario, TransportScenarioOutput,
};
pub use stack::MimStack;
