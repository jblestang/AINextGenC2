use std::collections::HashMap;

use mim_labeling::ConfidentialityLabel;

use crate::policy::SpifPolicy;

/// Registry of loaded SPIF policies keyed by policy identifier.
#[derive(Clone, Debug, Default)]
pub struct SpifRegistry {
    policies: HashMap<String, SpifPolicy>,
}

impl SpifRegistry {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(SpifPolicy::nato()).expect("nato");
        registry.register(SpifPolicy::acme()).expect("acme");
        registry.register(SpifPolicy::capco_us()).expect("capco");
        registry.register(SpifPolicy::uk_demo()).expect("uk");
        registry
    }

    pub fn register(&mut self, policy: SpifPolicy) -> Result<(), String> {
        if policy.policy_id.is_empty() {
            return Err("SPIF policy identifier is empty".into());
        }
        self.policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub fn load_xml(&mut self, xml: &str) -> Result<(), String> {
        let policy = crate::parser::parse_spif_xml(xml)?;
        self.register(policy)
    }

    pub fn get(&self, policy_id: &str) -> Option<&SpifPolicy> {
        self.policies.get(policy_id)
    }

    pub fn policy_for_label<'a>(&'a self, label: &ConfidentialityLabel) -> Option<&'a SpifPolicy> {
        self.get(&label.policy.identifier)
    }

    pub fn policies(&self) -> impl Iterator<Item = &SpifPolicy> {
        self.policies.values()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::parser;

    #[test]
    fn loads_acme_fixture() {
        let xml = include_str!("../fixtures/acme-policy.xml");
        let mut registry = SpifRegistry::new();
        registry.load_xml(xml).expect("load");
        assert!(registry.get("ACME").is_some());
    }

    #[test]
    fn defaults_include_national_policies() {
        let registry = SpifRegistry::with_defaults();
        assert!(registry.get("NATO").is_some());
        assert!(registry.get("US").is_some());
        assert!(registry.get("DEMO-UK").is_some());
        let parsed = parser::parse_spif_xml(include_str!("../fixtures/nato-4774-policy.xml"))
            .expect("nato xml");
        assert_eq!(parsed.policy_id, "NATO");
    }
}
