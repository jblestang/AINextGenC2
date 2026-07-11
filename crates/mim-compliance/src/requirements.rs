/// Target MIM compliance requirements for AINextGenC2.
#[derive(Clone, Debug, PartialEq)]
pub struct ComplianceRequirements {
    pub target_version: String,
    pub expected_counts: ExpectedCounts,
    pub min_object_coverage: f64,
    pub min_action_coverage: f64,
    pub min_code_list_coverage: f64,
    pub require_semantic_ids: bool,
    pub require_nil_reason_support: bool,
    pub require_metadata_support: bool,
    pub require_representation_terms: bool,
    pub require_zero_panic: bool,
}

/// Public MIM 5.1 scale targets from MIP documentation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExpectedCounts {
    pub object_types: u32,
    pub action_types: u32,
    pub code_lists: u32,
}

impl ExpectedCounts {
    pub fn mim_5_1() -> Self {
        Self {
            object_types: 2300,
            action_types: 500,
            code_lists: 400,
        }
    }
}

impl Default for ComplianceRequirements {
    fn default() -> Self {
        Self {
            target_version: "5.1.0".into(),
            expected_counts: ExpectedCounts::mim_5_1(),
            min_object_coverage: 1.0,
            min_action_coverage: 1.0,
            min_code_list_coverage: 1.0,
            require_semantic_ids: true,
            require_nil_reason_support: true,
            require_metadata_support: true,
            require_representation_terms: true,
            require_zero_panic: true,
        }
    }
}

impl ComplianceRequirements {
    pub fn mim_5_1_full() -> Self {
        Self::default()
    }
}
