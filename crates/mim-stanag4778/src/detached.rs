use mim_labeling::{ConfidentialityLabel, LabelError, LabelResult};
use mim_stanag4774::{Stanag4774Codec, Stanag4774Format};

/// Resolve a detached STANAG 4778 label reference (file path or file:// URI).
pub trait DetachedLabelResolver {
    fn resolve_label_xml(&self, uri: &str) -> LabelResult<String>;
}

/// File-system resolver for `file://` and absolute/relative paths.
#[derive(Clone, Debug, Default)]
pub struct FileDetachedLabelResolver;

impl DetachedLabelResolver for FileDetachedLabelResolver {
    fn resolve_label_xml(&self, uri: &str) -> LabelResult<String> {
        let path = uri.strip_prefix("file://").unwrap_or(uri);
        std::fs::read_to_string(path).map_err(|e| {
            LabelError::Parse(format!("failed to resolve detached label at {uri}: {e}"))
        })
    }
}

pub fn verify_detached_label(
    binding_label: &ConfidentialityLabel,
    label_uri: &str,
    resolver: &dyn DetachedLabelResolver,
) -> LabelResult<()> {
    let xml = resolver.resolve_label_xml(label_uri)?;
    let codec = Stanag4774Codec::new();
    let external = codec.deserialize(&xml, Stanag4774Format::Xml)?;
    if external.policy.identifier != binding_label.policy.identifier
        || external.classification != binding_label.classification
    {
        return Err(LabelError::Binding(
            "detached label content does not match binding label".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use mim_labeling::{ClassificationLevel, LabelPolicy};

    use super::*;

    #[test]
    fn resolves_file_uri_label() {
        let label = ConfidentialityLabel::new(LabelPolicy::nato(), ClassificationLevel::Secret);
        let codec = Stanag4774Codec::new();
        let xml = codec
            .serialize(&label, Stanag4774Format::Xml)
            .expect("serialize");
        let dir = std::env::temp_dir().join(format!("stanag4778-detached-{:?}", std::time::SystemTime::now()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("label.xml");
        std::fs::write(&path, &xml).expect("write");
        let uri = format!("file://{}", path.display());
        verify_detached_label(&label, &uri, &FileDetachedLabelResolver).expect("verify");
        let _ = std::fs::remove_dir_all(dir);
    }
}
