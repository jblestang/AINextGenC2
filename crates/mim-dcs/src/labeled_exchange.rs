use mim_labeling::{ConfidentialityLabel, LabelResult};
use mim_runtime::{InstanceStore, SerializationFormat, Serializer};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};
use mim_stanag4778::BindingDataObject;
use mim_ztdf::ZtdfPackage;
use serde::{Deserialize, Serialize};

/// A MIM exchange with DCS confidentiality labeling and bindings.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabeledMimExchange {
    pub label: ConfidentialityLabel,
    pub label_xml: String,
    pub mim_json: String,
    pub binding: Option<String>,
    pub ztdf_manifest: Option<String>,
}

impl LabeledMimExchange {
    pub fn build(
        store: &InstanceStore,
        serializer: &Serializer,
        label: &ConfidentialityLabel,
        binding_secret: &[u8],
        include_ztdf: bool,
    ) -> LabelResult<Self> {
        label.validate()?;
        let mim_json = serializer
            .serialize_store(store, SerializationFormat::Json)
            .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;

        let codec = Stanag4774Codec::new();
        let label_xml = codec.serialize(label, Stanag4774Format::Xml)?;

        let bdo = BindingDataObject::assertion_bound(label.clone(), mim_json.as_bytes(), binding_secret)?;
        let binding = serde_json::to_string_pretty(&bdo)
            .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;

        let ztdf_manifest = if include_ztdf {
            let package = ZtdfPackage::create(label, mim_json.as_bytes().to_vec(), binding_secret)?;
            Some(package.manifest_json()?)
        } else {
            None
        };

        Ok(Self {
            label: label.clone(),
            label_xml,
            mim_json,
            binding: Some(binding),
            ztdf_manifest,
        })
    }
}
