//! SPIF-driven policy administration — guard rules derive from loaded XML-SPIF policies.

use mim_labeling::{ClassificationLevel, DomainId, SecurityDomain};
use mim_spif::{SpifPolicy, SpifRegistry};

use crate::error::{PolicyError, PolicyResult};
use crate::pap::PolicyAdministrationPoint;
use crate::store::{CrossDomainPolicy, PolicyStore};

/// Apply SPIF policy metadata to the policy retrieval point (PRP).
pub fn apply_spif_to_store(store: &mut PolicyStore, registry: &SpifRegistry) -> PolicyResult<()> {
    for spif in registry.policies() {
        sync_domain_releasability(store, spif)?;
    }
    Ok(())
}

fn sync_domain_releasability(store: &mut PolicyStore, spif: &SpifPolicy) -> PolicyResult<()> {
    let releasable = spif
        .categories
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case("Releasable To"))
        .map(|c| c.allowed_values.clone())
        .unwrap_or_default();

    if releasable.is_empty() {
        return Ok(());
    }

    for domain in store.domains().cloned().collect::<Vec<_>>() {
        let updated = domain.with_releasable_to(releasable.clone());
        store.insert_domain(updated)?;
    }
    Ok(())
}

impl PolicyAdministrationPoint {
    /// Load SPIF policies into the PRP and align domain releasability with SPIF categories.
    pub fn with_spif_registry(registry: SpifRegistry) -> PolicyResult<Self> {
        let mut pap = Self::with_preset_high_to_low();
        for policy in registry.policies() {
            pap.store_mut().register_spif_policy(policy.clone())?;
        }
        apply_spif_to_store(pap.store_mut(), &registry)?;
        Ok(pap)
    }

    /// Register an additional SPIF policy and refresh domain constraints.
    pub fn load_spif_xml(&mut self, xml: &str) -> PolicyResult<()> {
        let mut registry = SpifRegistry::new();
        registry
            .load_xml(xml)
            .map_err(|e| PolicyError::Invalid(e))?;
        for policy in registry.policies() {
            self.store_mut().register_spif_policy(policy.clone())?;
        }
        apply_spif_to_store(self.store_mut(), &registry)
    }
}

pub fn guard_domains_from_spif(registry: &SpifRegistry) -> PolicyResult<(SecurityDomain, SecurityDomain)> {
    let nato = registry.get("NATO").ok_or_else(|| {
        PolicyError::NotFound("NATO SPIF policy required for cross-domain guard".into())
    })?;
    let releasable = nato
        .categories
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case("Releasable To"))
        .map(|c| c.allowed_values.clone())
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| vec!["USA".into(), "GBR".into()]);

    let high = SecurityDomain::new(
        "DOMAIN-HIGH",
        "High Side (SPIF-administered)",
        ClassificationLevel::Secret,
    )
    .with_releasable_to(releasable.clone());
    let low = SecurityDomain::new(
        "DOMAIN-LOW",
        "Low Side (SPIF-administered)",
        ClassificationLevel::Restricted,
    )
    .with_releasable_to(
        releasable
            .into_iter()
            .filter(|c| c == "USA" || c == "GBR")
            .collect(),
    );
    Ok((high, low))
}

pub fn cross_domain_policy_from_spif(
    source: DomainId,
    target: DomainId,
    spif: &SpifPolicy,
) -> CrossDomainPolicy {
    CrossDomainPolicy::new(
        format!("spif-{}-{}-to-{}", spif.policy_id, source.0, target.0),
        source,
        target,
    )
    .with_description(format!("SPIF policy {} cross-domain release rule", spif.policy_id))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_spif::SpifRegistry;

    use super::*;

    #[test]
    fn pap_loads_spif_and_updates_store() {
        let registry = SpifRegistry::with_defaults();
        let pap = PolicyAdministrationPoint::with_spif_registry(registry).expect("pap");
        assert!(!pap.store().spif_policies().is_empty());
        let high = pap
            .store()
            .domain(&DomainId::new("DOMAIN-HIGH"))
            .expect("high");
        assert!(!high.releasable_to.is_empty());
    }

    #[test]
    fn guard_domains_derive_releasability_from_nato_spif() {
        let registry = SpifRegistry::with_defaults();
        let (high, _low) = guard_domains_from_spif(&registry).expect("domains");
        assert!(high.releasable_to.contains(&"USA".into()));
    }
}
