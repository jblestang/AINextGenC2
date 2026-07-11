use crate::broker::ExchangeBroker;
use crate::error::TransportResult;

/// Result of applying replication journal entries from a publisher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicationApplyReport {
    pub applied: usize,
    pub skipped: usize,
    pub latest_sequence: u64,
}

/// Applies MIP4-IES replication journal entries from a publisher broker to a consumer.
#[derive(Clone, Debug, Default)]
pub struct ReplicationAgent;

impl ReplicationAgent {
    pub fn pull_and_apply(
        consumer: &mut ExchangeBroker,
        publisher: &ExchangeBroker,
        since: u64,
    ) -> TransportResult<ReplicationApplyReport> {
        let sync = publisher.sync_since(since);
        let mut applied = 0;
        let mut skipped = 0;

        for entry in sync.entries {
            if consumer.last_applied_sequence() >= entry.sequence {
                skipped += 1;
                continue;
            }
            consumer.apply_entry_from(publisher, &entry)?;
            applied += 1;
        }

        Ok(ReplicationApplyReport {
            applied,
            skipped,
            latest_sequence: sync.latest_sequence,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_core::SemanticId;
    use mim_runtime::PropertyValue;

    use super::*;
    use crate::message::{DeleteObjectRequest, PutObjectRequest};

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

    #[test]
    fn replicates_put_and_delete() {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        let instance = mim_runtime::MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "ALPHA"));
        publisher
            .put_object(PutObjectRequest {
                instance: instance.clone(),
            })
            .expect("put");
        let oid = instance.oid.clone();
        publisher
            .delete_object(DeleteObjectRequest { oid })
            .expect("delete");

        let report = ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).expect("apply");
        assert_eq!(report.applied, 2);
        assert_eq!(consumer.len(), 1);
        assert_eq!(consumer.active_count(), 0);
    }

    #[test]
    fn idempotent_replay_skips_seen_sequences() {
        let mut publisher = ExchangeBroker::new(test_registry());
        let mut consumer = ExchangeBroker::new(test_registry());
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        publisher
            .put_object(PutObjectRequest {
                instance: mim_runtime::MimInstance::new("Target", class_id)
                    .expect("instance")
                    .with_property(PropertyValue::string("nameText", "B")),
            })
            .expect("put");

        ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).expect("first");
        let second = ReplicationAgent::pull_and_apply(&mut consumer, &publisher, 0).expect("second");
        assert_eq!(second.skipped, 1);
        assert_eq!(second.applied, 0);
    }
}
