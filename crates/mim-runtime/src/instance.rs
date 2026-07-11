use indexmap::IndexMap;
use mim_core::{Nillable, NilReason, SemanticId};
use mim_model::Metadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::oid::ObjectIdentifier;

/// Typed property value in a MIM instance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PropertyValue {
    pub name: String,
    pub semantic_id: Option<SemanticId>,
    pub value: Nillable<Value>,
}

impl PropertyValue {
    pub fn string(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            semantic_id: None,
            value: Nillable::value(Value::String(value.into())),
        }
    }

    pub fn json(name: impl Into<String>, value: Value) -> Self {
        Self {
            name: name.into(),
            semantic_id: None,
            value: Nillable::value(value),
        }
    }

    pub fn number(name: impl Into<String>, value: f64) -> Self {
        Self::json(name, Value::from(value))
    }

    pub fn nil(name: impl Into<String>, reason: NilReason) -> Self {
        Self {
            name: name.into(),
            semantic_id: None,
            value: Nillable::Nil { reason },
        }
    }
}

/// Runtime instance of a MIM class.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MimInstance {
    pub oid: ObjectIdentifier,
    pub class_name: String,
    pub class_semantic_id: SemanticId,
    pub metadata: Metadata,
    pub properties: Vec<PropertyValue>,
    pub associations: IndexMap<String, Vec<ObjectIdentifier>>,
}

impl MimInstance {
    pub fn new(
        class_name: impl Into<String>,
        class_semantic_id: SemanticId,
    ) -> Result<Self, mim_core::MimError> {
        Ok(Self {
            oid: ObjectIdentifier::generate_urn(),
            class_name: class_name.into(),
            class_semantic_id,
            metadata: Metadata::default(),
            properties: Vec::new(),
            associations: IndexMap::new(),
        })
    }

    pub fn with_property(mut self, property: PropertyValue) -> Self {
        self.properties.push(property);
        self
    }

    pub fn property(&self, name: &str) -> Option<&PropertyValue> {
        self.properties.iter().find(|p| p.name == name)
    }

    pub fn set_association(
        &mut self,
        role: impl Into<String>,
        target: ObjectIdentifier,
    ) -> Result<(), mim_core::MimError> {
        let role = role.into();
        self.associations
            .entry(role)
            .or_default()
            .push(target);
        Ok(())
    }
}

/// In-memory repository of MIM instances.
#[derive(Clone, Debug, Default)]
pub struct InstanceStore {
    instances: IndexMap<ObjectIdentifier, MimInstance>,
}

impl InstanceStore {
    pub fn insert(&mut self, instance: MimInstance) -> ObjectIdentifier {
        let oid = instance.oid.clone();
        self.instances.insert(oid.clone(), instance);
        oid
    }

    pub fn get(&self, oid: &ObjectIdentifier) -> Option<&MimInstance> {
        self.instances.get(oid)
    }

    pub fn get_mut(&mut self, oid: &ObjectIdentifier) -> Option<&mut MimInstance> {
        self.instances.get_mut(oid)
    }

    pub fn len(&self) -> usize {
        self.instances.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    pub fn instances(&self) -> impl Iterator<Item = &MimInstance> {
        self.instances.values()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn instance_tracks_properties_and_associations() {
        let class_id =
            SemanticId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("id");
        let mut instance = MimInstance::new("Unit", class_id).expect("instance");
        instance = instance.with_property(PropertyValue::string("nameText", "Alpha Company"));

        let target = ObjectIdentifier::generate_urn();
        instance
            .set_association("parentOrganisation", target.clone())
            .expect("association");

        assert_eq!(instance.property("nameText").and_then(|p| p.value.as_option()), Some(&Value::String("Alpha Company".into())));
        assert_eq!(
            instance.associations.get("parentOrganisation").map(|v| v.len()),
            Some(1)
        );
    }
}
