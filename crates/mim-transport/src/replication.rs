use crate::broker::ExchangeBroker;
use crate::error::TransportResult;
use crate::message::IesOperation;
use crate::remote::FederationPublisher;
use crate::secured::SecuredExchangeBroker;

/// Result of applying replication journal entries from a publisher.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
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
        Self::apply_sync_response(consumer, publisher, sync)
    }

    /// Apply PEP-filtered journal entries from a secured publisher view.
    pub fn pull_and_apply_secured(
        consumer: &mut ExchangeBroker,
        publisher: &SecuredExchangeBroker,
        since: u64,
    ) -> TransportResult<ReplicationApplyReport> {
        let sync = publisher.sync_since(since);
        Self::apply_sync_response(consumer, publisher.broker(), sync)
    }

    /// Apply PEP-filtered journal for a specific subscriber identity.
    pub fn pull_and_apply_for_subject(
        consumer: &mut ExchangeBroker,
        publisher: &SecuredExchangeBroker,
        subject: mim_policy::SubjectAttributes,
        since: u64,
    ) -> TransportResult<ReplicationApplyReport> {
        let sync = publisher.sync_since_as(subject, since);
        Self::apply_sync_response(consumer, publisher.broker(), sync)
    }

    /// Pull journal entries from a remote HTTP publisher and apply locally.
    pub fn pull_and_apply_remote<P: FederationPublisher>(
        consumer: &mut ExchangeBroker,
        publisher: &P,
        since: u64,
    ) -> TransportResult<ReplicationApplyReport> {
        let sync = publisher.fetch_sync(since)?;
        let mut applied = 0;
        let mut skipped = 0;

        for entry in sync.entries {
            if consumer.last_applied_sequence() >= entry.sequence {
                skipped += 1;
                continue;
            }
            let instance = if entry.operation == IesOperation::PutObject {
                Some(publisher.fetch_instance(&entry.oid)?)
            } else {
                None
            };
            consumer.apply_remote_entry(&entry, instance)?;
            applied += 1;
        }

        Ok(ReplicationApplyReport {
            applied,
            skipped,
            latest_sequence: sync.latest_sequence,
        })
    }

    fn apply_sync_response(
        consumer: &mut ExchangeBroker,
        publisher: &ExchangeBroker,
        sync: crate::message::SyncResponse,
    ) -> TransportResult<ReplicationApplyReport> {
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

    trait WithMetadata {
        fn with_metadata(self, metadata: mim_model::Metadata) -> Self;
    }

    impl WithMetadata for mim_runtime::MimInstance {
        fn with_metadata(mut self, metadata: mim_model::Metadata) -> Self {
            self.metadata = metadata;
            self
        }
    }

    #[test]
    fn pep_filtered_replication_hides_secret_from_restricted_analyst() {
        use crate::secured::SecuredExchangeBroker;

        let registry = test_registry();
        let mut publisher = ExchangeBroker::new(registry.clone());
        let class_id = SemanticId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("id");
        let mut secret_meta = mim_model::Metadata::default();
        secret_meta.security.policy = mim_core::Nillable::value("NATO".into());
        secret_meta.security.classification = mim_core::Nillable::value("SECRET".into());
        secret_meta.security.releasability = mim_core::Nillable::value("USA".into());
        let secret = mim_runtime::MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "SECRET-1"))
            .with_metadata(secret_meta);
        publisher
            .put_object(PutObjectRequest { instance: secret })
            .expect("secret put");

        let mut restricted_meta = mim_model::Metadata::default();
        restricted_meta.security.policy = mim_core::Nillable::value("NATO".into());
        restricted_meta.security.classification = mim_core::Nillable::value("RESTRICTED".into());
        restricted_meta.security.releasability = mim_core::Nillable::value("USA".into());
        let restricted = mim_runtime::MimInstance::new("Target", class_id)
            .expect("instance")
            .with_property(PropertyValue::string("nameText", "RESTRICTED-1"))
            .with_metadata(restricted_meta);
        publisher
            .put_object(PutObjectRequest { instance: restricted })
            .expect("restricted put");

        let secured = SecuredExchangeBroker::from_preset(
            publisher,
            mim_policy::SubjectAttributes::new("publisher", mim_labeling::ClassificationLevel::Secret),
            "DOMAIN-HIGH",
        )
        .expect("secured");
        let restricted_subject =
            mim_policy::SubjectAttributes::new("analyst", mim_labeling::ClassificationLevel::Restricted);

        let sync = secured.sync_since_as(restricted_subject.clone(), 0);
        assert_eq!(sync.entries.len(), 1);

        let mut consumer = ExchangeBroker::new(registry);
        let report = ReplicationAgent::pull_and_apply_for_subject(
            &mut consumer,
            &secured,
            restricted_subject,
            0,
        )
        .expect("apply");
        assert_eq!(report.applied, 1);
        assert_eq!(consumer.active_count(), 1);
    }
}
