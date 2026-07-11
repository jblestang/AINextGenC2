use mim_labeling::{ConfidentialityLabel, LabelResult};
use mim_stanag4778::BindingDataObject;

use crate::manifest::{default_policy_b64, ZtdfManifest};

/// A complete ZTDF package: manifest + payload + optional BDO.
#[derive(Clone, Debug, PartialEq)]
pub struct ZtdfPackage {
    pub manifest: ZtdfManifest,
    pub payload: Vec<u8>,
    pub binding: Option<BindingDataObject>,
}

impl ZtdfPackage {
    pub fn create(
        label: &ConfidentialityLabel,
        payload: Vec<u8>,
        secret: &[u8],
    ) -> LabelResult<Self> {
        label.validate()?;
        let policy = default_policy_b64();
        let manifest = ZtdfManifest::for_mim_payload(label, &payload, secret, &policy)?;
        manifest.validate()?;
        let binding = BindingDataObject::assertion_bound(label.clone(), &payload, secret)?;
        Ok(Self {
            manifest,
            payload,
            binding: Some(binding),
        })
    }

    pub fn manifest_json(&self) -> LabelResult<String> {
        self.manifest.to_json()
    }

    pub fn verify(&self, secret: &[u8]) -> LabelResult<()> {
        self.manifest.validate()?;
        if let Some(binding) = &self.binding {
            binding.verify(&self.payload, Some(secret))?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{CategoryMarking, ClassificationLevel, LabelPolicy};

    use super::*;

    #[test]
    fn package_create_and_verify() {
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret)
            .with_category(CategoryMarking::releasable_to(vec!["USA".into()]));
        let payload = br#"{"modelVersion":"5.1.0"}"#.to_vec();
        let secret = b"ztfd-binding-secret-key-32bytes!";
        let package = ZtdfPackage::create(&label, payload, secret).expect("create");
        package.verify(secret).expect("verify");
        assert!(package.manifest_json().expect("json").contains("nato-label-1"));
    }
}
