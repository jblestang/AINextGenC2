//! XML-SPIF policy ingestion, XSD validation, and label validation (ADatP-4774.1).

pub mod parser;
pub mod policy;
pub mod registry;
pub mod validator;
pub mod xsd;

pub use policy::{SpifCategory, SpifCategoryType, SpifPolicy, SpifValidation, SpifVersionInfo};
pub use registry::SpifRegistry;
pub use validator::SpifValidator;
pub use xsd::{validate_spif_xsd, SpifSchemaProfile};
