use serde::{Deserialize, Serialize};

/// Top-level MIM object taxonomy branches (Figure 1, MIM 4.0 paper).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ObjectKind {
    Location,
    Organisation,
    Facility,
    Feature,
    Materiel,
    Person,
    InformationResource,
    Capability,
    Address,
    Event,
    PlanOrder,
    InformationGroup,
    OrganisationStructure,
    CandidateTargetList,
    RuleOfEngagement,
}

impl ObjectKind {
    pub const ALL: &'static [Self] = &[
        Self::Location,
        Self::Organisation,
        Self::Facility,
        Self::Feature,
        Self::Materiel,
        Self::Person,
        Self::InformationResource,
        Self::Capability,
        Self::Address,
        Self::Event,
        Self::PlanOrder,
        Self::InformationGroup,
        Self::OrganisationStructure,
        Self::CandidateTargetList,
        Self::RuleOfEngagement,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Location => "Location",
            Self::Organisation => "Organisation",
            Self::Facility => "Facility",
            Self::Feature => "Feature",
            Self::Materiel => "Materiel",
            Self::Person => "Person",
            Self::InformationResource => "InformationResource",
            Self::Capability => "Capability",
            Self::Address => "Address",
            Self::Event => "Event",
            Self::PlanOrder => "PlanOrder",
            Self::InformationGroup => "InformationGroup",
            Self::OrganisationStructure => "OrganisationStructure",
            Self::CandidateTargetList => "CandidateTargetList",
            Self::RuleOfEngagement => "RuleOfEngagement",
        }
    }
}

/// Top-level MIM action taxonomy branches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActionKind {
    Task,
    ActionEffect,
    ActionResource,
    ActionObjective,
    Establishment,
}

impl ActionKind {
    pub const ALL: &'static [Self] = &[
        Self::Task,
        Self::ActionEffect,
        Self::ActionResource,
        Self::ActionObjective,
        Self::Establishment,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Task => "Task",
            Self::ActionEffect => "ActionEffect",
            Self::ActionResource => "ActionResource",
            Self::ActionObjective => "ActionObjective",
            Self::Establishment => "Establishment",
        }
    }
}

/// A node in the MIM class taxonomy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaxonomyNode {
    pub name: String,
    pub semantic_id: mim_core::SemanticId,
    pub parent: Option<String>,
    pub object_kind: Option<ObjectKind>,
    pub action_kind: Option<ActionKind>,
    pub definition: String,
    pub package_path: String,
}

impl TaxonomyNode {
    pub fn is_object(&self) -> bool {
        self.object_kind.is_some()
    }

    pub fn is_action(&self) -> bool {
        self.action_kind.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_kind_names_match_mim_conventions() {
        assert_eq!(ObjectKind::Materiel.as_str(), "Materiel");
        assert_eq!(ActionKind::Task.as_str(), "Task");
    }
}
