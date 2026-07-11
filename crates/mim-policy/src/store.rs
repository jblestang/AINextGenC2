use indexmap::IndexMap;
use mim_labeling::{DomainId, SecurityDomain};
use serde::{Deserialize, Serialize};

use crate::error::{PolicyError, PolicyResult};

/// Cross-domain policy rule stored in the PRP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossDomainPolicy {
    pub id: String,
    pub description: String,
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub allow_downgrade: bool,
}

impl CrossDomainPolicy {
    pub fn new(
        id: impl Into<String>,
        source_domain: DomainId,
        target_domain: DomainId,
    ) -> Self {
        Self {
            id: id.into(),
            description: String::new(),
            source_domain,
            target_domain,
            allow_downgrade: true,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

/// Policy Retrieval Point — persistent store of domains and cross-domain rules.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyStore {
    domains: IndexMap<String, SecurityDomain>,
    cross_domain_policies: Vec<CrossDomainPolicy>,
    spif_policies: Vec<mim_spif::SpifPolicy>,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self {
            domains: IndexMap::new(),
            cross_domain_policies: Vec::new(),
            spif_policies: Vec::new(),
        }
    }

    pub fn domain(&self, id: &DomainId) -> Option<&SecurityDomain> {
        self.domains.get(&id.0)
    }

    pub fn domains(&self) -> impl Iterator<Item = &SecurityDomain> {
        self.domains.values()
    }

    pub fn cross_domain_policies(&self) -> &[CrossDomainPolicy] {
        &self.cross_domain_policies
    }

    pub fn policy_for_pair(
        &self,
        source: &DomainId,
        target: &DomainId,
    ) -> Option<&CrossDomainPolicy> {
        self.cross_domain_policies.iter().find(|policy| {
            policy.source_domain == *source && policy.target_domain == *target
        })
    }

    pub fn insert_domain(&mut self, domain: SecurityDomain) -> PolicyResult<()> {
        SecurityDomain::validate_id(&domain.id.0)?;
        self.domains.insert(domain.id.0.clone(), domain);
        Ok(())
    }

    pub fn insert_cross_domain_policy(&mut self, policy: CrossDomainPolicy) -> PolicyResult<()> {
        if policy.id.is_empty() {
            return Err(PolicyError::Invalid("policy id must not be empty".into()));
        }
        if self.domain(&policy.source_domain).is_none() {
            return Err(PolicyError::NotFound(format!(
                "source domain '{}' not registered",
                policy.source_domain.0
            )));
        }
        if self.domain(&policy.target_domain).is_none() {
            return Err(PolicyError::NotFound(format!(
                "target domain '{}' not registered",
                policy.target_domain.0
            )));
        }
        if self
            .cross_domain_policies
            .iter()
            .any(|existing| existing.id == policy.id)
        {
            return Err(PolicyError::Invalid(format!(
                "policy '{}' already exists",
                policy.id
            )));
        }
        self.cross_domain_policies.push(policy);
        Ok(())
    }

    pub fn remove_cross_domain_policy(&mut self, id: &str) -> PolicyResult<CrossDomainPolicy> {
        let position = self
            .cross_domain_policies
            .iter()
            .position(|policy| policy.id == id)
            .ok_or_else(|| PolicyError::NotFound(format!("policy '{id}' not found")))?;
        Ok(self.cross_domain_policies.remove(position))
    }

    pub fn register_spif_policy(&mut self, policy: mim_spif::SpifPolicy) -> PolicyResult<()> {
        if self
            .spif_policies
            .iter()
            .any(|p| p.policy_id == policy.policy_id)
        {
            return Err(PolicyError::Invalid(format!(
                "SPIF policy '{}' already registered",
                policy.policy_id
            )));
        }
        self.spif_policies.push(policy);
        Ok(())
    }

    pub fn spif_policies(&self) -> &[mim_spif::SpifPolicy] {
        &self.spif_policies
    }

    pub fn cross_domain_policy_for_spif(&self, spif_id: &str) -> Option<&CrossDomainPolicy> {
        self.cross_domain_policies
            .iter()
            .find(|p| p.description.contains(spif_id))
    }

    pub fn preset_high_to_low() -> Self {
        let mut store = Self::new();
        let _ = store.insert_domain(
            SecurityDomain::new("DOMAIN-HIGH", "High Side", mim_labeling::ClassificationLevel::Secret)
                .with_releasable_to(vec!["USA".into(), "GBR".into(), "DEU".into()]),
        );
        let _ = store.insert_domain(
            SecurityDomain::new(
                "DOMAIN-LOW",
                "Low Side",
                mim_labeling::ClassificationLevel::Restricted,
            )
            .with_releasable_to(vec!["USA".into(), "GBR".into()]),
        );
        let _ = store.insert_cross_domain_policy(
            CrossDomainPolicy::new("high-to-low", DomainId::new("DOMAIN-HIGH"), DomainId::new("DOMAIN-LOW"))
                .with_description("High-side to low-side cross-domain guard"),
        );
        store
    }

    pub fn preset_coalition() -> Self {
        let mut store = Self::new();
        let _ = store.insert_domain(
            SecurityDomain::new("DOMAIN-NATO", "NATO Core", mim_labeling::ClassificationLevel::Secret)
                .with_releasable_to(vec![
                    "USA".into(),
                    "GBR".into(),
                    "DEU".into(),
                    "FRA".into(),
                ]),
        );
        let _ = store.insert_domain(
            SecurityDomain::new(
                "DOMAIN-PARTNER",
                "Partner Nation",
                mim_labeling::ClassificationLevel::Secret,
            )
            .with_releasable_to(vec!["USA".into(), "GBR".into()]),
        );
        let _ = store.insert_cross_domain_policy(CrossDomainPolicy::new(
            "nato-to-partner",
            DomainId::new("DOMAIN-NATO"),
            DomainId::new("DOMAIN-PARTNER"),
        ));
        store
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn preset_registers_domains_and_policy() {
        let store = PolicyStore::preset_high_to_low();
        assert!(store.domain(&DomainId::new("DOMAIN-HIGH")).is_some());
        assert!(store
            .policy_for_pair(&DomainId::new("DOMAIN-HIGH"), &DomainId::new("DOMAIN-LOW"))
            .is_some());
    }
}
