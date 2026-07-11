use std::collections::HashSet;

use indexmap::IndexMap;
use mim_model::ModelRegistry;
use mim_runtime::{MimInstance, ObjectIdentifier, SerializationFormat, Serializer, Validator};

use crate::error::{TransportError, TransportResult};
use crate::filter::{instance_matches, parse_filter};
use crate::message::{
    DeleteObjectRequest, DeleteObjectResponse, GetByFilterRequest, GetByFilterResponse,
    GetByOidRequest, GetByOidResponse, IesOperation, JournalEntry, PutObjectRequest,
    PutObjectResponse, SyncResponse,
};

/// In-memory MIP4-IES exchange broker backing the REST service interface.
#[derive(Clone, Debug)]
pub struct ExchangeBroker {
    registry: ModelRegistry,
    store: IndexMap<ObjectIdentifier, MimInstance>,
    inactive: HashSet<ObjectIdentifier>,
    journal: Vec<JournalEntry>,
    sequence: u64,
}

impl ExchangeBroker {
    pub fn new(registry: ModelRegistry) -> Self {
        Self {
            registry,
            store: IndexMap::new(),
            inactive: HashSet::new(),
            journal: Vec::new(),
            sequence: 0,
        }
    }

    pub fn from_snapshot(
        registry: ModelRegistry,
        instances: Vec<MimInstance>,
        inactive: Vec<ObjectIdentifier>,
        journal: Vec<JournalEntry>,
        sequence: u64,
    ) -> Self {
        let store = instances
            .into_iter()
            .map(|instance| (instance.oid.clone(), instance))
            .collect();
        Self {
            registry,
            store,
            inactive: inactive.into_iter().collect(),
            journal,
            sequence,
        }
    }

    pub fn instances(&self) -> impl Iterator<Item = &MimInstance> {
        self.store.values()
    }

    pub fn inactive_oids(&self) -> impl Iterator<Item = &ObjectIdentifier> {
        self.inactive.iter()
    }

    pub fn journal(&self) -> &[JournalEntry] {
        &self.journal
    }

    pub fn latest_sequence(&self) -> u64 {
        self.sequence
    }

    pub fn sync_since(&self, since: u64) -> SyncResponse {
        let entries: Vec<JournalEntry> = self
            .journal
            .iter()
            .filter(|entry| entry.sequence > since)
            .cloned()
            .collect();
        SyncResponse {
            latest_sequence: self.sequence,
            entries,
        }
    }

    pub fn registry(&self) -> &ModelRegistry {
        &self.registry
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    pub fn active_count(&self) -> usize {
        self.store
            .keys()
            .filter(|oid| !self.inactive.contains(*oid))
            .count()
    }

    /// PutObject — publish or update a MIM instance.
    pub fn put_object(&mut self, request: PutObjectRequest) -> TransportResult<PutObjectResponse> {
        let validator = Validator::new(&self.registry);
        let report = validator.validate_instance(&request.instance);
        if !report.is_valid() {
            return Err(TransportError::Validation(format!(
                "{} validation issue(s) on PutObject",
                report.error_count()
            )));
        }

        let oid = request.instance.oid.clone();
        let created = !self.store.contains_key(&oid);
        self.store.insert(oid.clone(), request.instance);
        self.inactive.remove(&oid);
        self.record_journal(IesOperation::PutObject, oid.clone());

        Ok(PutObjectResponse { oid, created })
    }

    /// GetByOID — retrieve a single active instance.
    pub fn get_by_oid(&self, request: GetByOidRequest) -> TransportResult<GetByOidResponse> {
        if self.inactive.contains(&request.oid) {
            return Err(TransportError::Inactive(request.oid.to_string()));
        }

        let instance = self
            .store
            .get(&request.oid)
            .cloned()
            .ok_or_else(|| TransportError::NotFound(request.oid.to_string()))?;

        Ok(GetByOidResponse { instance })
    }

    /// GetByFilter — retrieve active instances matching criteria.
    pub fn get_by_filter(
        &self,
        request: GetByFilterRequest,
    ) -> TransportResult<GetByFilterResponse> {
        if let Some(expression) = request.filter.as_deref() {
            let filter = parse_filter(expression)?;
            let instances: Vec<MimInstance> = self
                .store
                .values()
                .filter(|instance| !self.inactive.contains(&instance.oid))
                .filter(|instance| instance_matches(instance, &filter))
                .cloned()
                .collect();
            let count = instances.len();
            let total = count;
            let instances = paginate_instances(instances, request.offset, request.limit);
            let count = instances.len();
            return Ok(GetByFilterResponse {
                instances,
                count,
                total,
            });
        }

        if request.class_name.trim().is_empty() {
            return Err(TransportError::InvalidRequest(
                "className or filter query parameter is required".into(),
            ));
        }

        let instances: Vec<MimInstance> = self
            .store
            .values()
            .filter(|instance| instance.class_name == request.class_name)
            .filter(|instance| !self.inactive.contains(&instance.oid))
            .filter(|instance| match (&request.property_name, &request.property_value) {
                (Some(name), Some(expected)) => instance
                    .property(name)
                    .and_then(|property| property.value.as_option())
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|actual| actual == expected),
                (Some(name), None) => instance.property(name).is_some(),
                (None, Some(_)) => false,
                (None, None) => true,
            })
            .cloned()
            .collect();

        let total = instances.len();
        let instances = paginate_instances(instances, request.offset, request.limit);
        let count = instances.len();
        Ok(GetByFilterResponse {
            instances,
            count,
            total,
        })
    }

    /// DeleteObject — soft-delete (mark inactive per MIP4-IES semantics).
    pub fn delete_object(
        &mut self,
        request: DeleteObjectRequest,
    ) -> TransportResult<DeleteObjectResponse> {
        if !self.store.contains_key(&request.oid) {
            return Err(TransportError::NotFound(request.oid.to_string()));
        }

        let deleted = self.inactive.insert(request.oid.clone());
        self.record_journal(IesOperation::DeleteObject, request.oid.clone());
        Ok(DeleteObjectResponse {
            oid: request.oid,
            deleted,
        })
    }

    fn record_journal(&mut self, operation: IesOperation, oid: ObjectIdentifier) {
        self.sequence = self.sequence.saturating_add(1);
        self.journal.push(JournalEntry {
            sequence: self.sequence,
            operation,
            oid,
        });
    }

    /// Publish an entire instance store via PutObject (bulk load).
    pub fn publish_store(
        &mut self,
        instances: impl IntoIterator<Item = MimInstance>,
    ) -> TransportResult<Vec<PutObjectResponse>> {
        instances
            .into_iter()
            .map(|instance| self.put_object(PutObjectRequest { instance }))
            .collect()
    }

    /// Serialize all active instances as a MIM exchange payload.
    pub fn serialize_active_store(&self) -> TransportResult<String> {
        let mut store = mim_runtime::InstanceStore::default();
        for instance in self.store.values() {
            if !self.inactive.contains(&instance.oid) {
                store.insert(instance.clone());
            }
        }

        let serializer = Serializer::new(self.registry.clone());
        serializer
            .serialize_store(&store, SerializationFormat::Json)
            .map_err(TransportError::from)
    }
}

pub(crate) fn paginate_instances(
    instances: Vec<MimInstance>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Vec<MimInstance> {
    let offset = offset.unwrap_or(0);
    let sliced: Vec<MimInstance> = instances.into_iter().skip(offset).collect();
    match limit {
        Some(limit) => sliced.into_iter().take(limit).collect(),
        None => sliced,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::SemanticId;
    use mim_runtime::PropertyValue;

    use super::*;

    fn test_registry() -> ModelRegistry {
        use mim_core::MimUri;
        use mim_model::manifest::{ModelElementKind, ModelElementSpec};
        use mim_model::TaxonomyNode;

        ModelRegistry::from_manifest(mim_model::MimManifest {
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

    fn target_instance(call_sign: &str) -> MimInstance {
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", call_sign))
    }

    #[test]
    fn filter_by_xpath_expression() {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = target_instance("HOSTILE-1");
        broker
            .put_object(PutObjectRequest {
                instance: instance.clone(),
            })
            .expect("put");

        let filtered = broker
            .get_by_filter(GetByFilterRequest {
                filter: Some("//Target[@nameText='HOSTILE-1']".into()),
                class_name: String::new(),
                property_name: None,
                property_value: None,
                limit: None,
                offset: None,
            })
            .expect("filter");
        assert_eq!(filtered.count, 1);
    }

    #[test]
    fn put_get_filter_delete_lifecycle() {
        let mut broker = ExchangeBroker::new(test_registry());
        let instance = target_instance("HOSTILE-1");
        let oid = instance.oid.clone();

        let put = broker
            .put_object(PutObjectRequest {
                instance: instance.clone(),
            })
            .expect("put");
        assert!(put.created);

        let got = broker
            .get_by_oid(GetByOidRequest { oid: oid.clone() })
            .expect("get");
        assert_eq!(got.instance.class_name, "Target");

        let filtered = broker
            .get_by_filter(GetByFilterRequest {
                class_name: "Target".into(),
                filter: None,
                property_name: Some("nameText".into()),
                property_value: Some("HOSTILE-1".into()),
                limit: None,
                offset: None,
            })
            .expect("filter");
        assert_eq!(filtered.count, 1);

        broker
            .delete_object(DeleteObjectRequest { oid: oid.clone() })
            .expect("delete");

        let err = broker
            .get_by_oid(GetByOidRequest { oid })
            .expect_err("inactive");
        assert!(matches!(err, TransportError::Inactive(_)));
    }

    #[test]
    fn rejects_invalid_put() {
        let mut broker = ExchangeBroker::new(test_registry());
        let class_id = SemanticId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("id");
        let bad = MimInstance::new("UnknownClass", class_id).expect("instance");
        let err = broker
            .put_object(PutObjectRequest { instance: bad })
            .expect_err("validation");
        assert!(matches!(err, TransportError::Validation(_)));
    }
}
