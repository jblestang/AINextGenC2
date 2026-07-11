//! Format-agnostic confidentiality labeling for MIM data-centric security.
//!
//! Bridges MIM `SecurityClassification` metadata to STANAG 4774/4778 and ZTDF
//! labeling pipelines used by cross-domain solutions.

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

pub mod classification;
pub mod domain;
pub mod error;
pub mod label;
pub mod policy;

pub use classification::ClassificationLevel;
pub use domain::{DomainId, SecurityDomain};
pub use error::{LabelError, LabelResult};
pub use label::{CategoryMarking, CategoryType, ConfidentialityLabel};
pub use policy::{LabelPolicy, NatoPolicy};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::Nillable;
    use mim_model::SecurityClassification;

    use super::*;

    #[test]
    fn classification_ordering() {
        assert!(ClassificationLevel::Secret > ClassificationLevel::Restricted);
        assert!(ClassificationLevel::Restricted.can_release_to(ClassificationLevel::Secret));
    }

    #[test]
    fn label_validates_mandatory_fields() {
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        assert!(label.validate().is_ok());
    }

    #[test]
    fn mim_security_round_trip() {
        let security = SecurityClassification {
            policy: Nillable::value("NATO".into()),
            classification: Nillable::value("SECRET".into()),
            releasability: Nillable::value("USA,GBR".into()),
        };
        let label = ConfidentialityLabel::from_mim_security(&security).expect("from");
        let back = label.to_mim_security();
        assert_eq!(back.classification.as_option().map(String::as_str), Some("SECRET"));
        assert_eq!(label.releasable_countries(), vec!["USA", "GBR"]);
    }

    #[test]
    fn releasable_category() {
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        assert_eq!(label.releasable_countries(), vec!["USA"]);
    }
}
