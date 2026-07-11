use mim_labeling::SecurityDomain;
use mim_policy::{
    AccessOperation, PolicyEnforcementPoint, PolicyError, PolicyInformationPoint,
    SubjectAttributes,
};
use mim_runtime::MimInstance;

use crate::broker::ExchangeBroker;
use crate::error::{TransportError, TransportResult};
use crate::message::{
    DeleteObjectRequest, DeleteObjectResponse, GetByFilterRequest, GetByFilterResponse,
    GetByOidRequest, GetByOidResponse, PutObjectRequest, PutObjectResponse,
};

/// MIP4-IES exchange broker with PEP-gated access control.
#[derive(Clone, Debug)]
pub struct SecuredExchangeBroker {
    inner: ExchangeBroker,
    pep: PolicyEnforcementPoint,
    subject: SubjectAttributes,
    domain: SecurityDomain,
}

impl SecuredExchangeBroker {
    pub fn new(
        inner: ExchangeBroker,
        pep: PolicyEnforcementPoint,
        subject: SubjectAttributes,
        domain: SecurityDomain,
    ) -> Self {
        Self {
            inner,
            pep,
            subject,
            domain,
        }
    }

    pub fn from_preset(
        inner: ExchangeBroker,
        subject: SubjectAttributes,
        domain_id: &str,
    ) -> TransportResult<Self> {
        let pep = PolicyEnforcementPoint::from_preset_high_to_low();
        let domain = pep
            .pdp()
            .store()
            .domain(&mim_labeling::DomainId::new(domain_id))
            .cloned()
            .ok_or_else(|| {
                TransportError::Validation(format!("unknown security domain '{domain_id}'"))
            })?;
        Ok(Self::new(inner, pep, subject, domain))
    }

    pub fn broker(&self) -> &ExchangeBroker {
        &self.inner
    }

    pub fn broker_mut(&mut self) -> &mut ExchangeBroker {
        &mut self.inner
    }

    pub fn pep(&self) -> &PolicyEnforcementPoint {
        &self.pep
    }

    pub fn subject(&self) -> &SubjectAttributes {
        &self.subject
    }

    pub fn domain(&self) -> &SecurityDomain {
        &self.domain
    }

    pub fn put_object(&mut self, request: PutObjectRequest) -> TransportResult<PutObjectResponse> {
        let label = Self::instance_label(&request.instance)?;
        self.pep
            .enforce_access(
                self.subject.clone(),
                &label,
                AccessOperation::Write,
                &self.domain,
            )
            .map_err(map_policy_error)?;
        self.inner.put_object(request)
    }

    pub fn get_by_oid(&self, request: GetByOidRequest) -> TransportResult<GetByOidResponse> {
        let response = self.inner.get_by_oid(request)?;
        let label = Self::instance_label(&response.instance)?;
        self.pep
            .enforce_access(
                self.subject.clone(),
                &label,
                AccessOperation::Read,
                &self.domain,
            )
            .map_err(map_policy_error)?;
        Ok(response)
    }

    pub fn get_by_filter(
        &self,
        request: GetByFilterRequest,
    ) -> TransportResult<GetByFilterResponse> {
        let response = self.inner.get_by_filter(request)?;
        let mut permitted = Vec::new();

        for instance in response.instances {
            let label = Self::instance_label(&instance)?;
            if self
                .pep
                .enforce_access(
                    self.subject.clone(),
                    &label,
                    AccessOperation::Read,
                    &self.domain,
                )
                .is_ok()
            {
                permitted.push(instance);
            }
        }

        let count = permitted.len();
        Ok(GetByFilterResponse {
            instances: permitted,
            count,
        })
    }

    pub fn delete_object(
        &mut self,
        request: DeleteObjectRequest,
    ) -> TransportResult<DeleteObjectResponse> {
        let existing = self.inner.get_by_oid(GetByOidRequest {
            oid: request.oid.clone(),
        })?;
        let label = Self::instance_label(&existing.instance)?;
        self.pep
            .enforce_access(
                self.subject.clone(),
                &label,
                AccessOperation::Delete,
                &self.domain,
            )
            .map_err(map_policy_error)?;
        self.inner.delete_object(request)
    }

    pub fn publish_store(
        &mut self,
        instances: impl IntoIterator<Item = MimInstance>,
    ) -> TransportResult<Vec<PutObjectResponse>> {
        instances
            .into_iter()
            .map(|instance| self.put_object(PutObjectRequest { instance }))
            .collect()
    }

    pub fn serialize_active_store(&self) -> TransportResult<String> {
        self.inner.serialize_active_store()
    }

    fn instance_label(instance: &MimInstance) -> TransportResult<mim_labeling::ConfidentialityLabel> {
        PolicyInformationPoint::label_from_security(&instance.metadata.security)
            .map_err(map_policy_error)
    }
}

fn map_policy_error(error: PolicyError) -> TransportError {
    match error {
        PolicyError::Denied(msg) => TransportError::Forbidden(msg),
        PolicyError::Validation(msg) => TransportError::Validation(msg),
        PolicyError::NotFound(msg) => TransportError::NotFound(msg),
        PolicyError::Invalid(msg) => TransportError::InvalidRequest(msg),
        PolicyError::Serialization(msg) => TransportError::Serialization(msg),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::SemanticId;
    use mim_labeling::ClassificationLevel;
    use mim_model::Metadata;
    use mim_runtime::PropertyValue;

    use super::*;
    use crate::broker::ExchangeBroker;

    fn test_registry() -> mim_model::ModelRegistry {
        use mim_core::MimUri;
        use mim_model::manifest::{ModelElementKind, ModelElementSpec};
        use mim_model::TaxonomyNode;

        mim_model::ModelRegistry::from_manifest(mim_model::MimManifest {
            version: "5.1.0".into(),
            release_date: "2020-09-28".into(),
            description: "minimal".into(),
            expected_object_types: 1,
            expected_action_types: 0,
            expected_code_lists: 0,
            taxonomy: vec![TaxonomyNode {
                name: "Target".into(),
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
                parent: None,
                object_kind: Some(mim_model::ObjectKind::InformationResource),
                action_kind: None,
                definition: "Target".into(),
                package_path: "Classifiers::Object::InformationResource::Target".into(),
            }],
            elements: vec![ModelElementSpec {
                name: "Target".into(),
                kind: ModelElementKind::Class,
                semantic_id: SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                    .expect("id"),
                uri: MimUri::parse(
                    "https://www.mimworld.org/mim/5.1.0/Classifiers/Object/InformationResource/Target",
                )
                .expect("uri"),
                package_path: "Classifiers::Object::InformationResource::Target".into(),
                definition: "Target".into(),
                parent_class: None,
                representation_term: None,
                representation_metadata: None,
                multiplicity_lower: None,
                multiplicity_upper: None,
                is_mandatory: false,
                is_nillable: true,
            }],
            code_lists: vec![],
        })
        .expect("registry")
    }

    fn labeled_target(classification: &str, call_sign: &str) -> MimInstance {
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        let mut metadata = Metadata::default();
        metadata.security.policy = mim_core::Nillable::value("NATO".into());
        metadata.security.classification = mim_core::Nillable::value(classification.into());
        metadata.security.releasability = mim_core::Nillable::value("USA".into());

        MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", call_sign))
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
    fn pep_denies_put_above_clearance() {
        let registry = test_registry();
        let mut secured = SecuredExchangeBroker::from_preset(
            ExchangeBroker::new(registry),
            SubjectAttributes::new("analyst", ClassificationLevel::Restricted),
            "DOMAIN-HIGH",
        )
        .expect("secured");
        let instance = labeled_target("SECRET", "HOSTILE-1");
        let err = secured
            .put_object(PutObjectRequest { instance })
            .expect_err("deny");
        assert!(matches!(err, TransportError::Forbidden(_)));
    }

    #[test]
    fn pep_filters_get_by_classification() {
        let registry = test_registry();
        let mut broker = ExchangeBroker::new(registry);
        broker
            .put_object(PutObjectRequest {
                instance: labeled_target("SECRET", "HOSTILE-1"),
            })
            .expect("secret");
        broker
            .put_object(PutObjectRequest {
                instance: labeled_target("RESTRICTED", "FRIEND-1"),
            })
            .expect("restricted");

        let secured = SecuredExchangeBroker::from_preset(
            broker,
            SubjectAttributes::new("analyst", ClassificationLevel::Restricted),
            "DOMAIN-HIGH",
        )
        .expect("secured");

        let filtered = secured
            .get_by_filter(GetByFilterRequest {
                class_name: "Target".into(),
                property_name: None,
                property_value: None,
            })
            .expect("filter");
        assert_eq!(filtered.count, 1);
        assert_eq!(
            filtered.instances[0]
                .property("nameText")
                .and_then(|p| p.value.as_option())
                .and_then(|v| v.as_str()),
            Some("FRIEND-1")
        );
    }
}
