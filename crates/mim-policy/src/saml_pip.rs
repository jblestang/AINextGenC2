//! SAML / OIDC bearer-token subject adapter (lab profile).
//!
//! Coalition IdPs often front LDAP with SAML assertions. This adapter accepts a
//! base64url-encoded JSON claims blob in `Authorization: Bearer` for exercises
//! where full SAML XML parsing is not yet wired.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use mim_labeling::ClassificationLevel;
use serde::Deserialize;

use crate::context::SubjectAttributes;
use crate::error::{PolicyError, PolicyResult};

/// Lab SAML/OIDC claims mapped to [`SubjectAttributes`].
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SamlSubjectClaims {
    pub subject_id: String,
    pub clearance: String,
    #[serde(default)]
    pub nationality: Option<String>,
    #[serde(default)]
    pub handling_caveats: Vec<String>,
    #[serde(default)]
    pub mission_id: Option<String>,
}

impl SamlSubjectClaims {
    pub fn to_subject_attributes(&self) -> PolicyResult<SubjectAttributes> {
        let clearance = ClassificationLevel::parse(&self.clearance).map_err(|e| {
            PolicyError::Invalid(format!("SAML clearance '{}': {e}", self.clearance))
        })?;
        let mut subject = SubjectAttributes::new(&self.subject_id, clearance);
        if let Some(nationality) = &self.nationality {
            subject = subject.with_nationality(nationality);
        }
        for caveat in &self.handling_caveats {
            subject = subject.with_handling_caveat(caveat);
        }
        if let Some(mission_id) = &self.mission_id {
            subject = subject.with_mission_id(mission_id);
        }
        Ok(subject)
    }
}

/// Parse `Authorization: Bearer <base64url-json-claims>` into subject attributes.
pub fn resolve_saml_bearer(authorization: &str) -> PolicyResult<SubjectAttributes> {
    let token = authorization
        .strip_prefix("Bearer ")
        .or_else(|| authorization.strip_prefix("bearer "))
        .ok_or_else(|| PolicyError::Invalid("expected Bearer authorization scheme".into()))?
        .trim();
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .or_else(|_| {
            use base64::engine::general_purpose::STANDARD;
            STANDARD.decode(token)
        })
        .map_err(|e| PolicyError::Invalid(format!("SAML bearer decode: {e}")))?;
    let claims: SamlSubjectClaims = serde_json::from_slice(&bytes)
        .map_err(|e| PolicyError::Invalid(format!("SAML bearer JSON: {e}")))?;
    claims.to_subject_attributes()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn resolves_bearer_claims() {
        let claims = serde_json::json!({
            "subjectId": "gbr-allied-analyst",
            "clearance": "SECRET",
            "nationality": "GBR"
        });
        let token = URL_SAFE_NO_PAD.encode(claims.to_string());
        let subject = resolve_saml_bearer(&format!("Bearer {token}")).expect("subject");
        assert_eq!(subject.subject_id, "gbr-allied-analyst");
        assert_eq!(subject.clearance, ClassificationLevel::Secret);
        assert_eq!(subject.nationality.as_deref(), Some("GBR"));
    }
}
