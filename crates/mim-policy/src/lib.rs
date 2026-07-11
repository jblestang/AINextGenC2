//! XACML-style policy plane for MIM data-centric security.
//!
//! - **PIP** (`PolicyInformationPoint`) — assembles subject/resource/environment attributes
//! - **PRP** (`PolicyStore`) — retrieves stored domain and cross-domain policies
//! - **PAP** (`PolicyAdministrationPoint`) — authors and manages policies
//! - **PDP** (`PolicyDecisionPoint`) — evaluates permit / deny / downgrade
//! - **PEP** (`PolicyEnforcementPoint`) — enforces decisions at access boundaries

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

pub mod context;
pub mod error;
pub mod pap;
pub mod pdp;
pub mod pep;
pub mod pip;
pub mod store;

pub use context::{
    AccessOperation, EnvironmentAttributes, PolicyContext, ResourceAttributes, SubjectAttributes,
};
pub use error::{PolicyError, PolicyResult};
pub use pap::PolicyAdministrationPoint;
pub use pdp::{PolicyDecision, PolicyDecisionPoint, PolicyEffect};
pub use pep::PolicyEnforcementPoint;
pub use pip::PolicyInformationPoint;
pub use store::{CrossDomainPolicy, PolicyStore};
