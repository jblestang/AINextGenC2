use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LabelingComplianceRequirements {
    pub require_stanag4774: bool,
    pub require_stanag4778: bool,
    pub require_ztdf: bool,
    pub require_dcs: bool,
    pub require_policy_plane: bool,
    pub require_assertion_binding: bool,
    pub require_nato_policy: bool,
    pub require_capco_policy: bool,
    pub require_uk_policy: bool,
    pub require_spif: bool,
    pub require_audit: bool,
    pub require_fips_crypto: bool,
}

impl Default for LabelingComplianceRequirements {
    fn default() -> Self {
        Self {
            require_stanag4774: true,
            require_stanag4778: true,
            require_ztdf: true,
            require_dcs: true,
            require_policy_plane: true,
            require_assertion_binding: true,
            require_nato_policy: true,
            require_capco_policy: true,
            require_uk_policy: true,
            require_spif: true,
            require_audit: true,
            require_fips_crypto: true,
        }
    }
}
