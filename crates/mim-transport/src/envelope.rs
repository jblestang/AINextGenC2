use mim_crypto::{SigningKey, VerifyingKey};
use mim_labeling::{ConfidentialityLabel, LabelResult};
use mim_stanag4778::RestEnvelope;

use crate::error::{TransportError, TransportResult};
use crate::message::PutObjectRequest;

/// Wrap a PutObject request in a STANAG 4778 REST envelope with NMBS assertion binding.
pub fn wrap_put_object(
    label: &ConfidentialityLabel,
    request: &PutObjectRequest,
    signing_key: &SigningKey,
) -> LabelResult<RestEnvelope> {
    let payload = serde_json::to_string(&request.instance)
        .map_err(|e| mim_labeling::LabelError::Serialization(e.to_string()))?;
    RestEnvelope::wrap(label, payload.as_bytes(), signing_key)
}

/// Verify a REST envelope and deserialize the embedded PutObject request.
pub fn unwrap_put_object(
    envelope: &RestEnvelope,
    verifying_key: &VerifyingKey,
) -> TransportResult<PutObjectRequest> {
    envelope
        .verify(verifying_key)
        .map_err(|e| TransportError::Forbidden(e.to_string()))?;
    let instance = serde_json::from_str(&envelope.payload)
        .map_err(|e| TransportError::Serialization(e.to_string()))?;
    Ok(PutObjectRequest { instance })
}

/// Serialize a REST envelope to JSON for HTTP transport.
pub fn envelope_to_json(envelope: &RestEnvelope) -> LabelResult<String> {
    envelope.to_json()
}

/// Parse a REST envelope from JSON received over HTTP.
pub fn envelope_from_json(data: &str) -> LabelResult<RestEnvelope> {
    RestEnvelope::from_json(data)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::SemanticId;
    use mim_crypto::conformance_keypair;
    use mim_labeling::{ClassificationLevel, LabelPolicy};
    use mim_model::Metadata;
    use mim_runtime::{MimInstance, PropertyValue};

    use super::*;

    fn labeled_target() -> MimInstance {
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        let mut metadata = Metadata::default();
        metadata.security.policy = mim_core::Nillable::value("NATO".into());
        metadata.security.classification = mim_core::Nillable::value("SECRET".into());
        MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "HOSTILE-1"))
            .with_metadata(metadata)
    }

    trait WithMetadata {
        fn with_metadata(self, metadata: Metadata) -> Self;
    }

    impl WithMetadata for MimInstance {
        fn with_metadata(mut self, metadata: Metadata) -> Self {
            self.metadata = metadata;
            self
        }
    }

    #[test]
    fn put_object_rest_envelope_round_trip() {
        let keys = conformance_keypair().expect("keys");
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let request = PutObjectRequest {
            instance: labeled_target(),
        };
        let envelope = wrap_put_object(&label, &request, keys.signing_key()).expect("wrap");
        let restored = unwrap_put_object(&envelope, keys.verifying_key()).expect("unwrap");
        assert_eq!(restored.instance.class_name, "Target");
    }
}
