//! Live FMN OpenLDAP E2E — queries real directory (CI docker-compose.ldap-ci.yml).

use std::path::PathBuf;

use mim_labeling::ClassificationLevel;
use mim_policy::{LdapSubjectDirectory, SubjectResolver};

fn ci_ldap_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/fmn-ldap-pip-ci.toml")
}

fn load_live_directory() -> LdapSubjectDirectory {
    let path = ci_ldap_config_path();
    std::env::set_var("MIM_LDAP_BIND_PASSWORD", "ci-ldap-admin");
    LdapSubjectDirectory::load_path(&path).expect("load CI LDAP PIP config")
}

#[test]
#[ignore = "requires FMN OpenLDAP (CI: docker-compose.ldap-ci.yml; local: scripts/ci/ldap-e2e.sh)"]
fn live_ldap_resolves_gbr_allied_analyst_by_uid() {
    let dir = load_live_directory();
    let subject = dir
        .resolve_principal("gbr-allied-analyst")
        .expect("resolve uid");
    assert_eq!(subject.subject_id, "gbr-allied-analyst");
    assert_eq!(subject.clearance, ClassificationLevel::Secret);
    assert_eq!(subject.nationality.as_deref(), Some("GBR"));
}

#[test]
#[ignore = "requires FMN OpenLDAP (CI: docker-compose.ldap-ci.yml; local: scripts/ci/ldap-e2e.sh)"]
fn live_ldap_resolves_usa_sensor_operator_by_principal_dn() {
    let dir = load_live_directory();
    let subject = dir
        .resolve_principal("uid=usa-sensor-operator,ou=USA,ou=operators,dc=nato,dc=int")
        .expect("resolve DN");
    assert_eq!(subject.subject_id, "usa-sensor-operator");
    assert_eq!(subject.nationality.as_deref(), Some("USA"));
}

#[test]
#[ignore = "requires FMN OpenLDAP (CI: docker-compose.ldap-ci.yml; local: scripts/ci/ldap-e2e.sh)"]
fn live_ldap_resolves_mtls_cert_cn_via_fmn_mapping() {
    let dir = load_live_directory();
    let resolver = SubjectResolver::new(dir);
    let subject = resolver
        .resolve("gbr-analyst.nato.mil")
        .expect("resolve cert CN");
    assert_eq!(subject.subject_id, "gbr-allied-analyst");
    assert_eq!(subject.nationality.as_deref(), Some("GBR"));
}

#[test]
#[ignore = "requires FMN OpenLDAP (CI: docker-compose.ldap-ci.yml; local: scripts/ci/ldap-e2e.sh)"]
fn live_ldap_resolves_restricted_clearance() {
    let dir = load_live_directory();
    let subject = dir
        .resolve_principal("usa-restricted-analyst")
        .expect("resolve restricted");
    assert_eq!(subject.clearance, ClassificationLevel::Restricted);
}
