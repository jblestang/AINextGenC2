use mim_labeling::SecurityDomain;

use crate::error::PolicyResult;
use crate::store::{CrossDomainPolicy, PolicyStore};

/// Policy Administration Point — authors and manages policies in the PRP.
#[derive(Clone, Debug)]
pub struct PolicyAdministrationPoint {
    store: PolicyStore,
}

impl PolicyAdministrationPoint {
    pub fn new(store: PolicyStore) -> Self {
        Self { store }
    }

    pub fn with_preset_high_to_low() -> Self {
        Self::new(PolicyStore::preset_high_to_low())
    }

    pub fn with_preset_coalition() -> Self {
        Self::new(PolicyStore::preset_coalition())
    }

    pub fn store(&self) -> &PolicyStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut PolicyStore {
        &mut self.store
    }

    pub fn into_store(self) -> PolicyStore {
        self.store
    }

    pub fn register_domain(&mut self, domain: SecurityDomain) -> PolicyResult<()> {
        self.store.insert_domain(domain)
    }

    pub fn add_cross_domain_policy(&mut self, policy: CrossDomainPolicy) -> PolicyResult<()> {
        self.store.insert_cross_domain_policy(policy)
    }

    pub fn remove_cross_domain_policy(&mut self, id: &str) -> PolicyResult<CrossDomainPolicy> {
        self.store.remove_cross_domain_policy(id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{ClassificationLevel, DomainId};

    use super::*;

    #[test]
    fn pap_registers_domain_and_policy() {
        let mut pap = PolicyAdministrationPoint::new(PolicyStore::new());
        pap.register_domain(SecurityDomain::new(
            "DOMAIN-A",
            "A",
            ClassificationLevel::Secret,
        ))
        .expect("domain a");
        pap.register_domain(SecurityDomain::new(
            "DOMAIN-B",
            "B",
            ClassificationLevel::Restricted,
        ))
        .expect("domain b");
        pap.add_cross_domain_policy(CrossDomainPolicy::new(
            "a-to-b",
            DomainId::new("DOMAIN-A"),
            DomainId::new("DOMAIN-B"),
        ))
        .expect("policy");
        assert_eq!(pap.store().cross_domain_policies().len(), 1);
    }
}
