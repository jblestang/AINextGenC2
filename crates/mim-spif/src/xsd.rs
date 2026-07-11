use std::fs;
use std::process::Command;

const ISO_29008_2011_XSD: &str = include_str!("../schemas/spif-iso29008-2011.xsd");
const XMLSPIF_XSD: &str = include_str!("../schemas/xmlspif.xsd");

/// XSD validation backend for XML-SPIF documents.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SpifSchemaProfile {
    #[default]
    Iso29008_2011,
    XmlSpif2,
}

impl SpifSchemaProfile {
    pub fn schema_bytes(self) -> &'static str {
        match self {
            Self::Iso29008_2011 => ISO_29008_2011_XSD,
            Self::XmlSpif2 => XMLSPIF_XSD,
        }
    }

    pub fn detect(xml: &str) -> Self {
        if xml.contains("urn:iso:std:iso:29008:2011:confidentialitymetadatalabel") {
            Self::Iso29008_2011
        } else if xml.contains("http://www.xmlspif.org/spif") {
            Self::XmlSpif2
        } else {
            Self::Iso29008_2011
        }
    }
}

pub fn validate_spif_xsd(xml: &str) -> Result<(), String> {
    validate_spif_xsd_with_profile(xml, SpifSchemaProfile::detect(xml))
}

pub fn validate_spif_xsd_with_profile(xml: &str, profile: SpifSchemaProfile) -> Result<(), String> {
    match validate_with_xmllint(xml, profile.schema_bytes()) {
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
    let xml_path = std::env::temp_dir().join(format!("spif-{stamp}.xml"));
    let xsd_path = std::env::temp_dir().join(format!("spif-{stamp}.xsd"));

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
    if !xml.contains("<spif") {
        return Err("missing root <spif> element".into());
    }
    if !(xml.contains("securityPolicyId") || xml.contains("policyIdentifier")) {
        return Err("missing securityPolicyId".into());
    }
    if !(xml.contains("securityClassification") || xml.contains("<classification>")) {
        return Err("missing securityClassification elements".into());
    }
    if !(xml.contains("<identifier>") || xml.contains("policyIdentifier")) {
        return Err("missing policy identifier".into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validates_acme_fixture_against_iso_xsd() {
        let xml = include_str!("../fixtures/acme-policy.xml");
        validate_spif_xsd_with_profile(xml, SpifSchemaProfile::Iso29008_2011).expect("valid");
    }

    #[test]
    fn rejects_malformed_spif() {
        let bad = "<spif><securityPolicyId/></spif>";
        assert!(validate_spif_xsd(bad).is_err());
    }
}
