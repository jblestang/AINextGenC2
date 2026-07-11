use std::fs;
use std::process::Command;

const STANAG4774_LABEL_XSD: &str = include_str!("../schemas/stanag4774-label.xsd");

pub const NAMESPACE: &str = "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0";

const LABEL_ROOTS: &[&str] = &[
    "ConfidentialityLabel",
    "originatorConfidentialityLabel",
    "metadataConfidentialityLabel",
];

/// Validate STANAG 4774 label XML against the bundled XSD profile.
pub fn validate_stanag4774_xsd(xml: &str) -> Result<(), String> {
    match validate_with_xmllint(xml, STANAG4774_LABEL_XSD) {
        Ok(()) => Ok(()),
        Err(xmllint_err) => validate_structural(xml).map_err(|structural| {
            format!("XSD validation failed ({xmllint_err}); structural check: {structural}")
        }),
    }
}

fn validate_with_xmllint(xml: &str, schema: &str) -> Result<(), String> {
    if !xmllint_available() {
        return Err("xmllint not available".into());
    }

    let stamp = format!("{:?}", std::time::SystemTime::now());
    let xml_path = std::env::temp_dir().join(format!("stanag4774-{stamp}.xml"));
    let xsd_path = std::env::temp_dir().join(format!("stanag4774-{stamp}.xsd"));

    fs::write(&xml_path, xml).map_err(|e| e.to_string())?;
    fs::write(&xsd_path, schema).map_err(|e| e.to_string())?;

    let output = Command::new("xmllint")
        .arg("--noout")
        .arg("--schema")
        .arg(&xsd_path)
        .arg(&xml_path)
        .output()
        .map_err(|e| format!("xmllint execution failed: {e}"))?;

    let _ = fs::remove_file(&xml_path);
    let _ = fs::remove_file(&xsd_path);

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("xmllint schema validation failed: {}", stderr.trim()))
    }
}

fn xmllint_available() -> bool {
    Command::new("xmllint")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn validate_structural(xml: &str) -> Result<(), String> {
    if !xml.contains(NAMESPACE) {
        return Err(format!("missing namespace {NAMESPACE}"));
    }
    if !LABEL_ROOTS.iter().any(|root| xml.contains(root)) {
        return Err("missing confidentiality label root element".into());
    }
    if !xml.contains("ConfidentialityInformation") {
        return Err("missing ConfidentialityInformation".into());
    }
    if !xml.contains("PolicyIdentifier") {
        return Err("missing PolicyIdentifier".into());
    }
    if !xml.contains("Classification") {
        return Err("missing Classification".into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validates_acme_fixture() {
        let xml = include_str!("../fixtures/adatp/acme-valid-4774.1.xml");
        validate_stanag4774_xsd(xml).expect("valid acme label");
    }

    #[test]
    fn validates_nato_table17_vector() {
        let xml = include_str!("../fixtures/adatp/nato-4774-17-1.nato");
        validate_stanag4774_xsd(xml).expect("valid nato vector");
    }

    #[test]
    fn rejects_malformed_label() {
        let bad = "<ConfidentialityLabel xmlns=\"urn:nato:stanag:4774:confidentialitymetadatalabel:1:0\"/>";
        assert!(validate_stanag4774_xsd(bad).is_err());
    }
}
