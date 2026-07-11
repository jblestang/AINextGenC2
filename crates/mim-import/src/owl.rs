use std::collections::{BTreeMap, BTreeSet};

use mim_core::MimResult;

/// Parsed OWL/RDF-XML ontology relevant to MIM import.
#[derive(Clone, Debug, Default)]
pub struct OwlModel {
    pub classes: BTreeMap<String, OwlClass>,
    pub properties: BTreeMap<String, OwlProperty>,
    pub enumerations: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default)]
pub struct OwlClass {
    pub name: String,
    pub label: Option<String>,
    pub parents: Vec<String>,
    pub is_enumeration: bool,
}

#[derive(Clone, Debug, Default)]
pub struct OwlProperty {
    pub name: String,
    pub label: Option<String>,
    pub property_type: OwlPropertyKind,
    pub domain: Option<String>,
    pub range: Option<String>,
    pub parents: Vec<String>,
    pub inverse_of: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OwlPropertyKind {
    #[default]
    Object,
    Data,
}

impl OwlModel {
    pub fn parse_xml(data: &str) -> MimResult<Self> {
        owl_xml::parse(data)
    }

    /// Count OWL property references in raw XML (opening tags, closing tags, restrictions).
    pub fn count_xml_property_references(data: &str) -> usize {
        data.lines()
            .filter(|line| line.contains("ObjectProperty") || line.contains("DatatypeProperty"))
            .count()
    }

    pub fn class_names(&self) -> impl Iterator<Item = &String> {
        self.classes.keys()
    }

    pub fn descendants_of(&self, root: &str) -> BTreeSet<String> {
        let mut result = BTreeSet::new();
        let mut queue = vec![root.to_owned()];
        while let Some(current) = queue.pop() {
            for (name, class) in &self.classes {
                if class.parents.iter().any(|parent| parent == &current) && result.insert(name.clone())
                {
                    queue.push(name.clone());
                }
            }
        }
        result
    }

    /// Walk OWL `subClassOf` parents from `class_name` upward (cycle-safe).
    pub fn ancestors_of(&self, class_name: &str) -> Vec<String> {
        let mut ancestors = Vec::new();
        let mut enqueued = BTreeSet::from([class_name.to_owned()]);
        let mut queue = vec![class_name.to_owned()];

        while let Some(current) = queue.pop() {
            let Some(class) = self.classes.get(&current) else {
                continue;
            };
            for parent in &class.parents {
                if enqueued.insert(parent.clone()) {
                    ancestors.push(parent.clone());
                    queue.push(parent.clone());
                }
            }
        }
        ancestors
    }

    /// Fill missing property domains/ranges from `owl:inverseOf` partners.
    pub fn resolve_inverse_domains(&mut self) {
        let updates: Vec<(String, Option<String>, Option<String>)> = self
            .properties
            .iter()
            .filter_map(|(_name, property)| {
                property.inverse_of.as_ref().map(|partner| {
                    (
                        partner.clone(),
                        property.range.clone(),
                        property.domain.clone(),
                    )
                })
            })
            .collect();

        for (partner, domain, range) in updates {
            let entry = self.properties.entry(partner).or_insert_with(|| OwlProperty {
                name: "unknown".into(),
                ..OwlProperty::default()
            });
            if entry.domain.is_none() {
                entry.domain = domain;
            }
            if entry.range.is_none() {
                entry.range = range;
            }
        }
    }
}

mod owl_xml {
    use quick_xml::events::{BytesEnd, BytesStart, Event};
    use quick_xml::Reader;

    use super::{OwlClass, OwlModel};
    use mim_core::MimError;

    #[derive(Default)]
    struct ParserState {
        current_class: Option<String>,
        current_property: Option<String>,
        pending_domain: Option<String>,
        pending_range: Option<String>,
        in_label: bool,
        in_one_of: bool,
        one_of_owner: Option<String>,
        one_of_values: Vec<String>,
    }

    impl ParserState {
        fn new() -> Self {
            Self::default()
        }
    }

    pub fn parse(data: &str) -> Result<OwlModel, MimError> {
        let mut reader = Reader::from_str(data);
        reader.config_mut().trim_text(true);

        let mut model = OwlModel::default();
        let mut state = ParserState::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => handle_start(e, &mut model, &mut state)?,
                Ok(Event::Empty(ref e)) => handle_empty(e, &mut model, &mut state)?,
                Ok(Event::End(ref e)) => handle_end(e, &mut model, &mut state)?,
                Ok(Event::Text(ref e)) if state.in_label => {
                    let text = String::from_utf8_lossy(e.as_ref()).into_owned();
                    if !text.is_empty() {
                        if let Some(class_name) = state.current_class.clone() {
                            let entry = model.classes.entry(class_name).or_insert_with(|| OwlClass {
                                name: "unknown".into(),
                                ..OwlClass::default()
                            });
                            entry.label = Some(text);
                        } else if let Some(prop_name) = state.current_property.clone() {
                            let entry = model
                                .properties
                                .entry(prop_name)
                                .or_insert_with(|| super::OwlProperty {
                                    name: "unknown".into(),
                                    ..super::OwlProperty::default()
                                });
                            entry.label = Some(text);
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(err) => return Err(MimError::Parse(err.to_string())),
            }
            buf.clear();
        }

        Ok(model)
    }

    fn handle_start(
        e: &BytesStart<'_>,
        model: &mut OwlModel,
        state: &mut ParserState,
    ) -> Result<(), MimError> {
        let name = local_name(e);
        match name.as_str() {
            "Class" | "Thing" => {
                if let Some(class_name) = class_ref(e) {
                    if state.in_one_of {
                        state.one_of_values.push(class_name);
                    } else {
                        state.current_class = Some(class_name.clone());
                        state.current_property = None;
                        model.classes.entry(class_name.clone()).or_insert_with(|| OwlClass {
                            name: class_name.clone(),
                            ..OwlClass::default()
                        });
                    }
                }
            }
            "ObjectProperty" | "DatatypeProperty" => {
                if let Some(prop_name) = class_ref(e) {
                    state.current_property = Some(prop_name.clone());
                    state.current_class = None;
                    let kind = if name == "ObjectProperty" {
                        super::OwlPropertyKind::Object
                    } else {
                        super::OwlPropertyKind::Data
                    };
                    let mut property = super::OwlProperty {
                        name: prop_name.clone(),
                        property_type: kind,
                        ..super::OwlProperty::default()
                    };
                    if let Some(domain) = state.pending_domain.take() {
                        property.domain = Some(domain);
                    }
                    if let Some(range) = state.pending_range.take() {
                        property.range = Some(range);
                    }
                    model.properties.insert(prop_name.clone(), property);
                }
            }
            "subPropertyOf" => {
                if let (Some(child), Some(parent)) =
                    (state.current_property.clone(), resource_ref(e))
                {
                    let entry = model.properties.entry(child.clone()).or_insert_with(|| super::OwlProperty {
                        name: child.clone(),
                        ..super::OwlProperty::default()
                    });
                    if !entry.parents.contains(&parent) {
                        entry.parents.push(parent);
                    }
                }
            }
            "inverseOf" => {
                if let (Some(child), Some(partner)) =
                    (state.current_property.clone(), resource_ref(e))
                {
                    let entry = model.properties.entry(child.clone()).or_insert_with(|| super::OwlProperty {
                        name: child.clone(),
                        ..super::OwlProperty::default()
                    });
                    entry.inverse_of = Some(partner);
                }
            }
            "domain" => {
                if let Some(domain) = resource_ref(e) {
                    if let Some(prop) = &state.current_property {
                        if let Some(entry) = model.properties.get_mut(prop) {
                            entry.domain = Some(domain.clone());
                        }
                    } else {
                        state.pending_domain = Some(domain);
                    }
                }
            }
            "range" => {
                if let Some(range) = resource_ref(e) {
                    if let Some(prop) = &state.current_property {
                        if let Some(entry) = model.properties.get_mut(prop) {
                            entry.range = Some(range.clone());
                        }
                    } else {
                        state.pending_range = Some(range);
                    }
                }
            }
            "subClassOf" => {
                if let (Some(child), Some(parent)) = (state.current_class.clone(), resource_ref(e))
                {
                    add_parent(model, &child, parent);
                }
            }
            "oneOf" => {
                state.in_one_of = true;
                state.one_of_values.clear();
                state.one_of_owner = state.current_class.clone();
            }
            "label" => state.in_label = true,
            _ => {}
        }
        Ok(())
    }

    fn handle_empty(
        e: &BytesStart<'_>,
        model: &mut OwlModel,
        state: &mut ParserState,
    ) -> Result<(), MimError> {
        let name = local_name(e);
        if name == "Class" || name == "Thing" {
            if let Some(class_name) = class_ref(e) {
                if state.in_one_of {
                    state.one_of_values.push(class_name);
                } else {
                    state.current_class = Some(class_name.clone());
                    model.classes.entry(class_name.clone()).or_insert_with(|| OwlClass {
                        name: class_name.clone(),
                        ..OwlClass::default()
                    });
                }
            }
        } else if name == "ObjectProperty" || name == "DatatypeProperty" {
            if let Some(prop_name) = class_ref(e) {
                state.current_property = Some(prop_name.clone());
                state.current_class = None;
                let kind = if name == "ObjectProperty" {
                    super::OwlPropertyKind::Object
                } else {
                    super::OwlPropertyKind::Data
                };
                let mut property = super::OwlProperty {
                    name: prop_name.clone(),
                    property_type: kind,
                    ..super::OwlProperty::default()
                };
                if let Some(domain) = state.pending_domain.take() {
                    property.domain = Some(domain);
                }
                if let Some(range) = state.pending_range.take() {
                    property.range = Some(range);
                }
                model.properties.insert(prop_name.clone(), property);
            }
        } else if name == "subClassOf" {
            if let (Some(child), Some(parent)) = (state.current_class.clone(), resource_ref(e)) {
                add_parent(model, &child, parent);
            }
        } else if name == "domain" {
            if let Some(domain) = resource_ref(e) {
                if let Some(prop) = &state.current_property {
                    if let Some(entry) = model.properties.get_mut(prop) {
                        entry.domain = Some(domain);
                    }
                } else {
                    state.pending_domain = Some(domain);
                }
            }
        } else if name == "range" {
            if let Some(range) = resource_ref(e) {
                if let Some(prop) = &state.current_property {
                    if let Some(entry) = model.properties.get_mut(prop) {
                        entry.range = Some(range);
                    }
                } else {
                    state.pending_range = Some(range);
                }
            }
        } else if name == "inverseOf" {
            if let (Some(child), Some(partner)) =
                (state.current_property.clone(), resource_ref(e))
            {
                let entry = model.properties.entry(child.clone()).or_insert_with(|| super::OwlProperty {
                    name: child.clone(),
                    ..super::OwlProperty::default()
                });
                entry.inverse_of = Some(partner);
            }
        }
        Ok(())
    }

    fn handle_end(
        e: &BytesEnd<'_>,
        model: &mut OwlModel,
        state: &mut ParserState,
    ) -> Result<(), MimError> {
        let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
        match name.as_str() {
            "oneOf" if state.in_one_of => {
                if let Some(owner) = state.one_of_owner.take() {
                    if !state.one_of_values.is_empty() {
                        model
                            .enumerations
                            .insert(owner.clone(), state.one_of_values.clone());
                        if let Some(class) = model.classes.get_mut(&owner) {
                            class.is_enumeration = true;
                        }
                    }
                }
                state.in_one_of = false;
                state.one_of_values.clear();
            }
            "label" => state.in_label = false,
            "Class" => state.current_class = None,
            "ObjectProperty" | "DatatypeProperty" => {
                if let Some(prop) = state.current_property.clone() {
                    if let Some(entry) = model.properties.get_mut(&prop) {
                        if entry.domain.is_none() {
                            if let Some(domain) = state.pending_domain.take() {
                                entry.domain = Some(domain);
                            }
                        }
                        if entry.range.is_none() {
                            if let Some(range) = state.pending_range.take() {
                                entry.range = Some(range);
                            }
                        }
                    }
                }
                state.current_property = None;
            }
            _ => {}
        }
        Ok(())
    }

    fn add_parent(model: &mut OwlModel, child: &str, parent: String) {
        let entry = model.classes.entry(child.to_owned()).or_insert_with(|| OwlClass {
            name: child.to_owned(),
            ..OwlClass::default()
        });
        if !entry.parents.contains(&parent) {
            entry.parents.push(parent);
        }
    }

    fn local_name(e: &BytesStart<'_>) -> String {
        String::from_utf8_lossy(e.local_name().as_ref()).into_owned()
    }

    fn class_ref(e: &BytesStart<'_>) -> Option<String> {
        attribute_value(e, b"about")
            .or_else(|| attribute_value(e, b"ID"))
            .map(normalize_ref)
    }

    fn resource_ref(e: &BytesStart<'_>) -> Option<String> {
        attribute_value(e, b"resource").map(normalize_ref)
    }

    fn attribute_value(e: &BytesStart<'_>, key: &[u8]) -> Option<String> {
        e.attributes()
            .filter_map(|attr| attr.ok())
            .find(|attr| {
                attr.key.as_ref() == key
                    || attr.key.local_name().as_ref() == key
            })
            .and_then(|attr| String::from_utf8(attr.value.into_owned()).ok())
    }

    fn normalize_ref(value: String) -> String {
        let trimmed = value.trim();
        if let Some((_, local)) = trimmed.rsplit_once('#') {
            return local.to_owned();
        }
        if let Some((_, local)) = trimmed.rsplit_once('/') {
            return local.to_owned();
        }
        trimmed.trim_start_matches('#').to_owned()
    }
}

pub fn normalize_owl_ref(value: &str) -> String {
    let trimmed = value.trim();
    if let Some((_, local)) = trimmed.rsplit_once('#') {
        return local.to_owned();
    }
    if let Some((_, local)) = trimmed.rsplit_once('/') {
        return local.to_owned();
    }
    trimmed.trim_start_matches('#').to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SAMPLE: &str = r##"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:owl="http://www.w3.org/2002/07/owl#"
         xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#">
  <owl:Class rdf:ID="ACTION"/>
  <owl:Class rdf:ID="ACTION-EVENT">
    <rdfs:subClassOf rdf:resource="#ACTION"/>
    <rdfs:label>Action Event</rdfs:label>
  </owl:Class>
  <owl:Class rdf:ID="UnitRangeCode">
    <owl:equivalentClass>
      <owl:oneOf rdf:parseType="Collection">
        <owl:Thing rdf:ID="CloseRange"/>
        <owl:Thing rdf:ID="ShortRange"/>
      </owl:oneOf>
    </owl:equivalentClass>
  </owl:Class>
  <owl:ObjectProperty rdf:ID="producedTrack">
    <rdfs:domain rdf:resource="#ACTION-EVENT"/>
    <rdfs:range rdf:resource="#ACTION"/>
    <rdfs:label>produced track</rdfs:label>
  </owl:ObjectProperty>
  <owl:DatatypeProperty rdf:ID="speed">
    <rdfs:domain rdf:resource="#MilitaryConvoy"/>
    <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#decimal"/>
    <rdfs:label>speed</rdfs:label>
  </owl:DatatypeProperty>
</rdf:RDF>"##;

    #[test]
    fn parses_classes_parents_labels_and_enums() {
        let model = OwlModel::parse_xml(SAMPLE).expect("parse");
        assert!(model.classes.contains_key("ACTION"));
        assert!(model.classes.contains_key("ACTION-EVENT"));
        let action_event = model.classes.get("ACTION-EVENT").expect("class");
        assert_eq!(action_event.parents, vec!["ACTION"]);
        assert_eq!(action_event.label.as_deref(), Some("Action Event"));
        assert_eq!(
            model.enumerations.get("UnitRangeCode").map(Vec::as_slice),
            Some(&["CloseRange".to_owned(), "ShortRange".to_owned()][..])
        );
        assert!(model.properties.contains_key("producedTrack"));
        assert!(model.properties.contains_key("speed"));
        let produced = model.properties.get("producedTrack").expect("prop");
        assert_eq!(produced.domain.as_deref(), Some("ACTION-EVENT"));
    }

    #[test]
    fn parses_full_uri_domain_and_range() {
        const SAMPLE: &str = r##"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:owl="http://www.w3.org/2002/07/owl#"
         xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#">
  <owl:Class rdf:about="http://example.org/ont#MilitaryConvoy"/>
  <owl:DatatypeProperty rdf:about="http://example.org/ont#daySpeed">
    <rdfs:domain rdf:resource="http://example.org/ont#MilitaryConvoy"/>
    <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#decimal"/>
  </owl:DatatypeProperty>
</rdf:RDF>"##;
        let model = OwlModel::parse_xml(SAMPLE).expect("parse");
        let speed = model.properties.get("daySpeed").expect("property");
        assert_eq!(speed.domain.as_deref(), Some("MilitaryConvoy"));
        assert_eq!(speed.range.as_deref(), Some("decimal"));
    }

    #[test]
    fn parses_self_closing_inverse_property_stubs() {
        const SAMPLE: &str = r##"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:owl="http://www.w3.org/2002/07/owl#"
         xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#">
  <owl:Class rdf:ID="ACTION-CONTEXT"/>
  <owl:Class rdf:ID="ACTION-CONTEXT-STATUS"/>
  <owl:ObjectProperty rdf:ID="AC-has-ACS">
    <rdfs:domain rdf:resource="#ACTION-CONTEXT"/>
    <rdfs:range rdf:resource="#ACTION-CONTEXT-STATUS"/>
    <owl:inverseOf rdf:resource="#ACS-is-ascribed-to-AC"/>
  </owl:ObjectProperty>
  <owl:ObjectProperty rdf:ID="ACS-is-ascribed-to-AC"/>
</rdf:RDF>"##;
        let mut model = OwlModel::parse_xml(SAMPLE).expect("parse");
        assert_eq!(model.properties.len(), 2);
        model.resolve_inverse_domains();
        let inverse = model.properties.get("ACS-is-ascribed-to-AC").expect("inverse");
        assert_eq!(inverse.domain.as_deref(), Some("ACTION-CONTEXT-STATUS"));
        assert_eq!(inverse.range.as_deref(), Some("ACTION-CONTEXT"));
    }

    #[test]
    fn ancestors_walks_subclass_chain() {
        const SAMPLE: &str = r##"<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:owl="http://www.w3.org/2002/07/owl#"
         xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#">
  <owl:Class rdf:ID="ACTION"/>
  <owl:Class rdf:ID="ACTION-EVENT">
    <rdfs:subClassOf rdf:resource="#ACTION"/>
  </owl:Class>
  <owl:Class rdf:ID="FIRING-EVENT">
    <rdfs:subClassOf rdf:resource="#ACTION-EVENT"/>
  </owl:Class>
</rdf:RDF>"##;
        let model = OwlModel::parse_xml(SAMPLE).expect("parse");
        let ancestors = model.ancestors_of("FIRING-EVENT");
        assert!(ancestors.contains(&"ACTION-EVENT".to_owned()));
        assert!(ancestors.contains(&"ACTION".to_owned()));
    }

    #[test]
    fn normalize_owl_ref_strips_uri_fragments() {
        assert_eq!(
            super::normalize_owl_ref("http://example.org/ont#ACTION-EVENT"),
            "ACTION-EVENT"
        );
        assert_eq!(super::normalize_owl_ref("#REFERENCE"), "REFERENCE");
    }
}
