use serde::{Deserialize, Serialize};

use crate::error::{LabelError, LabelResult};

/// NATO classification levels ordered by sensitivity (low to high).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClassificationLevel {
    Unmarked,
    /// ACME SPIF day-zero classification.
    Public,
    Unclassified,
    /// ACME SPIF internal-use classification.
    Internal,
    Restricted,
    Confidential,
    Secret,
    CosmicTopSecret,
}

impl ClassificationLevel {
    pub const ALL: &'static [Self] = &[
        Self::Unmarked,
        Self::Public,
        Self::Unclassified,
        Self::Internal,
        Self::Restricted,
        Self::Confidential,
        Self::Secret,
        Self::CosmicTopSecret,
    ];

    pub fn parse(value: &str) -> LabelResult<Self> {
        let normalized = value.trim().to_ascii_uppercase();
        match normalized.as_str() {
            "UNMARKED" => Ok(Self::Unmarked),
            "PUBLIC" => Ok(Self::Public),
            "UNCLASSIFIED" | "NATO UNCLASSIFIED" => Ok(Self::Unclassified),
            "INTERNAL" => Ok(Self::Internal),
            "RESTRICTED" | "NATO RESTRICTED" => Ok(Self::Restricted),
            "CONFIDENTIAL" | "NATO CONFIDENTIAL" | "NATO/EAPC CONFIDENTIAL"
            | "NATO/KFOR CONFIDENTIAL" => Ok(Self::Confidential),
            "SECRET" | "NATO SECRET" => Ok(Self::Secret),
            "TOP SECRET" | "COSMIC TOP SECRET" | "COSMIC_TOP_SECRET" => {
                Ok(Self::CosmicTopSecret)
            }
            other => Err(LabelError::InvalidClassification(other.to_owned())),
        }
    }

    pub fn as_stanag_str(self) -> &'static str {
        match self {
            Self::Unmarked => "UNMARKED",
            Self::Public => "PUBLIC",
            Self::Unclassified => "UNCLASSIFIED",
            Self::Internal => "INTERNAL",
            Self::Restricted => "RESTRICTED",
            Self::Confidential => "CONFIDENTIAL",
            Self::Secret => "SECRET",
            Self::CosmicTopSecret => "COSMIC TOP SECRET",
        }
    }

    pub fn can_release_to(self, target_max: Self) -> bool {
        self <= target_max
    }
}
