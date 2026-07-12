//! Pluggable subject directory backends (fixture LDAP, live LDAP, SAML).

use crate::context::SubjectAttributes;
use crate::error::PolicyResult;

/// Resolves authenticated principals to PEP subject attributes.
pub trait SubjectDirectory: Send + Sync {
    fn resolve_principal(&self, principal: &str) -> PolicyResult<SubjectAttributes>;
    fn resolve_cert_cn(&self, cn: &str) -> PolicyResult<SubjectAttributes>;
    fn resolve_cert_fingerprint(&self, fingerprint: &str) -> PolicyResult<SubjectAttributes>;

    fn resolve_cert_cn_or_principal(&self, identity: &str) -> PolicyResult<SubjectAttributes> {
        self.resolve_cert_cn(identity)
            .or_else(|_| self.resolve_principal(identity))
    }
}
