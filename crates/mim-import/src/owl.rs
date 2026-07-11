use std::collections::{BTreeMap, BTreeSet};

use mim_core::MimResult;

/// Parsed subset of an OWL/RDF-XML ontology relevant to MIM import.
#[derive(Clone, Debug, Default)]
pub struct OwlModel {
    pub classes: BTreeMap<String, OwlClass>,
    pub enumerations: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default)]
pub struct OwlClass {
    pub name: String,
    pub label: Option<String>,
    pub parents: Vec<String>,
    pub is_enumeration: bool,
}

impl OwlModel {
    pub fn parse_xml(data: &str) -> MimResult<Self> {
        owl_xml::parse(data)
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
}

mod owl_xml {
    use quick_xml::events::{BytesEnd, BytesStart, Event};
    use quick_xml::Reader;

    use super::{OwlClass, OwlModel};
    use mim_core::MimError;

    #[derive(Default)]
    struct ParserState {
        current_class: Option<String>,
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
                    if let Some(class_name) = state.current_class.clone() {
                        let text = String::from_utf8_lossy(e.as_ref()).into_owned();
                        if !text.is_empty() {
                            let entry = model.classes.entry(class_name).or_insert_with(|| OwlClass {
                                name: "unknown".into(),
                                ..OwlClass::default()
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
                        model.classes.entry(class_name.clone()).or_insert_with(|| OwlClass {
                            name: class_name.clone(),
                            ..OwlClass::default()
                        });
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
        } else if name == "subClassOf" {
            if let (Some(child), Some(parent)) = (state.current_class.clone(), resource_ref(e)) {
                add_parent(model, &child, parent);
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
        value.trim().trim_start_matches('#').to_owned()
    }
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
    }
}
