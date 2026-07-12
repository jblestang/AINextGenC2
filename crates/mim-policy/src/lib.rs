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
pub mod downgrade;
pub mod error;
pub mod ldap_pip;
pub mod live_ldap;
pub mod pap;
pub mod pdp;
pub mod pep;
pub mod pip;
pub mod saml_pip;
pub mod spif_admin;
pub mod store;
pub mod subject_directory;
pub mod subject_resolver;

pub use context::{
    AccessOperation, EnvironmentAttributes, PolicyContext, ResourceAttributes, SubjectAttributes,
};
pub use downgrade::{downgraded_label_for_target, requires_downgrade, DowngradeConfig};
pub use error::{PolicyError, PolicyResult};
pub use pap::PolicyAdministrationPoint;
pub use pdp::{PolicyDecision, PolicyDecisionPoint, PolicyEffect};
pub use pep::PolicyEnforcementPoint;
pub use ldap_pip::{
    CertFingerprintMapping, CertSubjectMapping, LdapPipConfig, LdapServerConfig,
    LdapSubjectDirectory, LdapSubjectEntry,
};
pub use pip::PolicyInformationPoint;
pub use saml_pip::{resolve_saml_bearer, SamlSubjectClaims};
pub use subject_directory::SubjectDirectory;
pub use subject_resolver::SubjectResolver;
pub use spif_admin::{
    apply_spif_to_store, cross_domain_policy_from_spif, guard_domains_from_spif,
};
pub use store::{CrossDomainPolicy, PolicyStore};
