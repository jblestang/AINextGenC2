//! Identity resolution for PEP — LDAP directory + optional fallback subject.

use crate::context::SubjectAttributes;
use crate::error::{PolicyError, PolicyResult};
use crate::ldap_pip::LdapSubjectDirectory;

/// Resolves authenticated principals to PEP subject attributes.
#[derive(Clone, Debug)]
pub struct SubjectResolver {
    ldap: LdapSubjectDirectory,
    fallback: Option<SubjectAttributes>,
}

impl SubjectResolver {
    pub fn new(ldap: LdapSubjectDirectory) -> Self {
        Self {
            ldap,
            fallback: None,
        }
    }

    pub fn with_fallback(mut self, fallback: SubjectAttributes) -> Self {
        self.fallback = Some(fallback);
        self
    }

    pub fn ldap(&self) -> &LdapSubjectDirectory {
        &self.ldap
    }

/// Resolve from mTLS certificate CN, LDAP principal, SAML bearer, or subject id.
    pub fn resolve(&self, identity: &str) -> PolicyResult<SubjectAttributes> {
        if identity.len() == 64 && identity.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(subject) = self.ldap.resolve_cert_fingerprint(identity) {
                return Ok(subject);
            }
        }
        self.ldap
            .resolve_cert_cn_or_principal(identity)
            .or_else(|_| {
                if let Some(fallback) = &self.fallback {
                    if fallback.subject_id == identity {
                        return Ok(fallback.clone());
                    }
                }
                Err(PolicyError::NotFound(format!(
                    "unresolved identity '{identity}'"
                )))
            })
    }

    pub fn resolve_cert_fingerprint(&self, fingerprint: &str) -> PolicyResult<SubjectAttributes> {
        self.ldap.resolve_cert_fingerprint(fingerprint)
    }

    pub fn from_env() -> PolicyResult<Self> {
        let path = std::env::var("MIM_LDAP_PIP_CONFIG")
            .unwrap_or_else(|_| "config/fmn-ldap-pip.toml".into());
        let ldap = LdapSubjectDirectory::load_path(&path)?;
        Ok(Self::new(ldap))
    }

    pub fn conformance() -> PolicyResult<Self> {
        Ok(Self::new(LdapSubjectDirectory::conformance()?))
    }

    /// Resolve from a SAML/OIDC bearer authorization header value.
    pub fn resolve_saml_bearer(&self, authorization: &str) -> PolicyResult<SubjectAttributes> {
        crate::saml_pip::resolve_saml_bearer(authorization)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::ClassificationLevel;

    use super::*;

    #[test]
    fn resolves_known_cert_cn() {
        let resolver = SubjectResolver::conformance().expect("resolver");
        let subject = resolver.resolve("usa-analyst.nato.mil").expect("subject");
        assert_eq!(subject.clearance, ClassificationLevel::Secret);
    }
}
