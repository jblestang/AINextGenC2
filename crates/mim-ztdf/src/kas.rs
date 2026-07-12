//! KAS client abstraction for ZTDF content-key unwrap (ACP-240 / OpenTDF keyAccess).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use mim_crypto::{selected_provider, ContentEncryptionKey, SigningKey};
use mim_labeling::LabelResult;

use crate::manifest::ZtdfManifest;

/// Key Access Server client — unwraps the CEK from a ZTDF manifest.
pub trait KasClient: Send + Sync {
    fn unwrap_content_key(&self, manifest: &ZtdfManifest) -> LabelResult<ContentEncryptionKey>;
}

/// In-process KAS using a local RSA private key (lab / conformance).
#[derive(Clone, Debug)]
pub struct LocalKasClient {
    signing_key: SigningKey,
}

impl LocalKasClient {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

impl KasClient for LocalKasClient {
    fn unwrap_content_key(&self, manifest: &ZtdfManifest) -> LabelResult<ContentEncryptionKey> {
        let wrapped = STANDARD
            .decode(&manifest.encryption_information.key_wrap.wrapped_key)
            .map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))?;
        selected_provider()
            .unwrap_key_rsa_oaep_sha256(&self.signing_key, &wrapped)
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))
    }
}

/// Remote KAS HTTP stub (POST wrapped key + policy; returns CEK bytes).
#[derive(Clone, Debug)]
pub struct HttpKasClient {
    endpoint: String,
    client_cn: Option<String>,
}

impl HttpKasClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client_cn: None,
        }
    }

    pub fn with_client_cn(mut self, cn: impl Into<String>) -> Self {
        self.client_cn = Some(cn.into());
        self
    }

    pub fn from_env() -> LabelResult<Self> {
        let endpoint = std::env::var("MIM_KAS_ENDPOINT").map_err(|_| {
            mim_labeling::LabelError::Validation("MIM_KAS_ENDPOINT not set".into())
        })?;
        Ok(Self::new(endpoint))
    }
}

impl KasClient for HttpKasClient {
    fn unwrap_content_key(&self, manifest: &ZtdfManifest) -> LabelResult<ContentEncryptionKey> {
        let body = serde_json::json!({
            "keyId": manifest.encryption_information.key_wrap.key_id,
            "wrappedKey": manifest.encryption_information.key_wrap.wrapped_key,
            "policy": manifest.encryption_information.policy,
        });
        let mut request = ureq::post(&self.endpoint).set("Content-Type", "application/json");
        if let Some(cn) = &self.client_cn {
            request = request.set("X-MIM-Client-CN", cn);
        }
        let response = request
            .send_json(body)
            .map_err(|e| mim_labeling::LabelError::Binding(format!("KAS POST: {e}")))?;
        if response.status() != 200 {
            return Err(mim_labeling::LabelError::Binding(format!(
                "KAS returned HTTP {}",
                response.status()
            )));
        }
        let cek_b64: String = response
            .into_string()
            .map_err(|e| mim_labeling::LabelError::Binding(e.to_string()))?;
        let bytes = STANDARD
            .decode(cek_b64.trim())
            .map_err(|e| mim_labeling::LabelError::Parse(e.to_string()))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| mim_labeling::LabelError::Binding("KAS CEK must be 32 bytes".into()))?;
        Ok(ContentEncryptionKey::from_bytes(array))
    }
}
