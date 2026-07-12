//! Live LDAP directory search (operational mode when `fixture_mode = false`).

use std::time::Duration;

use crate::context::SubjectAttributes;
use crate::error::{PolicyError, PolicyResult};
use crate::ldap_pip::{LdapPipConfig, LdapSubjectEntry};

/// LDAP attribute names mapped to NATO clearance fields.
const ATTR_CLEARANCE: &str = "natoClearance";
const ATTR_NATIONALITY: &str = "natoNationality";
const ATTR_MISSION: &str = "natoMissionId";
const ATTR_HANDLING_CAVEATS: &str = "natoHandlingCaveats";

/// Search a live LDAP directory for a principal and map attributes to subject.
pub fn search_principal(config: &LdapPipConfig, principal: &str) -> PolicyResult<SubjectAttributes> {
    let ldap_cfg = &config.ldap;
    let filter = build_search_filter(config, principal);

    if ldap_cfg.server.starts_with("http://") || ldap_cfg.server.starts_with("https://") {
        return search_http_gateway(&ldap_cfg.server, principal, &filter);
    }

    search_ldap3(ldap_cfg, principal, &filter)
}

fn search_http_gateway(
    endpoint: &str,
    principal: &str,
    filter: &str,
) -> PolicyResult<SubjectAttributes> {
    let body = serde_json::json!({
        "principal": principal,
        "filter": filter,
    });
    let response = ureq::post(endpoint)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(5))
        .send_json(body)
        .map_err(|e| PolicyError::Invalid(format!("LDAP HTTP gateway {endpoint}: {e}")))?;
    if response.status() != 200 {
        return Err(PolicyError::NotFound(format!(
            "LDAP HTTP gateway returned HTTP {}",
            response.status()
        )));
    }
    let entry: LdapSubjectEntry = response
        .into_json()
        .map_err(|e| PolicyError::Invalid(format!("LDAP HTTP gateway JSON: {e}")))?;
    entry.to_subject_attributes()
}

fn search_ldap3(
    ldap_cfg: &crate::ldap_pip::LdapServerConfig,
    principal: &str,
    filter: &str,
) -> PolicyResult<SubjectAttributes> {
    use ldap3::{LdapConn, Scope, SearchEntry};

    let bind_password = std::env::var("MIM_LDAP_BIND_PASSWORD").ok();
    let mut ldap = LdapConn::new(&ldap_cfg.server)
        .map_err(|e| PolicyError::Invalid(format!("LDAP connect {}: {e}", ldap_cfg.server)))?;
    if let Some(bind_dn) = &ldap_cfg.bind_dn {
        ldap.simple_bind(bind_dn, bind_password.as_deref().unwrap_or(""))
            .map_err(|e| PolicyError::Invalid(format!("LDAP bind: {e}")))?
            .success()
            .map_err(|e| PolicyError::Invalid(format!("LDAP bind failed: {e}")))?;
    }

    let (entries, _) = ldap
        .search(&ldap_cfg.base_dn, Scope::Subtree, filter, vec![
            ATTR_CLEARANCE,
            ATTR_NATIONALITY,
            ATTR_MISSION,
            ATTR_HANDLING_CAVEATS,
            "uid",
            "cn",
        ])
        .map_err(|e| PolicyError::Invalid(format!("LDAP search: {e}")))?
        .success()
        .map_err(|e| PolicyError::Invalid(format!("LDAP search failed: {e}")))?;

    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| PolicyError::NotFound(format!("LDAP principal '{principal}' not found")))?;
    let search_entry = SearchEntry::construct(entry);
    let attrs = search_entry.attrs;

    let clearance = attrs
        .get(ATTR_CLEARANCE)
        .and_then(|v| v.first())
        .ok_or_else(|| PolicyError::Invalid("LDAP entry missing natoClearance".into()))?;
    let subject_id = attrs
        .get("uid")
        .or_else(|| attrs.get("cn"))
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| principal_uid_for_search(principal));

    let ldap_entry = LdapSubjectEntry {
        principal: principal.to_owned(),
        subject_id,
        clearance: clearance.clone(),
        nationality: attrs.get(ATTR_NATIONALITY).and_then(|v| v.first()).cloned(),
        handling_caveats: attrs
            .get(ATTR_HANDLING_CAVEATS)
            .cloned()
            .unwrap_or_default(),
        mission_id: attrs.get(ATTR_MISSION).and_then(|v| v.first()).cloned(),
    };
    ldap_entry.to_subject_attributes()
}

/// Extract the `uid` token from an FMN principal DN or bare subject id.
fn principal_uid_for_search(principal: &str) -> String {
    let trimmed = principal.trim();
    if let Some(rest) = trimmed.strip_prefix("uid=") {
        return rest
            .split(',')
            .next()
            .unwrap_or(trimmed)
            .to_owned();
    }
    trimmed.to_owned()
}

pub(crate) fn build_search_filter(config: &LdapPipConfig, principal: &str) -> String {
    let ldap_cfg = &config.ldap;
    let filter_template = ldap_cfg
        .search_filter
        .as_deref()
        .unwrap_or("(uid={principal})");
    let uid = principal_uid_for_search(principal);
    filter_template.replace("{principal}", &uid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ldap_pip::{LdapPipConfig, LdapServerConfig};

    #[test]
    fn search_filter_uses_uid_from_principal_dn() {
        let config = LdapPipConfig {
            ldap: LdapServerConfig {
                server: "ldap://localhost".into(),
                base_dn: "ou=operators,dc=nato,dc=int".into(),
                bind_dn: None,
                search_filter: Some("(uid={principal})".into()),
                fixture_mode: false,
            },
            entries_file: None,
            cert_mappings: vec![],
            cert_fingerprint_mappings: vec![],
            default_domain_id: None,
        };
        let filter = build_search_filter(
            &config,
            "uid=gbr-allied-analyst,ou=GBR,ou=operators,dc=nato,dc=int",
        );
        assert_eq!(filter, "(uid=gbr-allied-analyst)");
    }
}
