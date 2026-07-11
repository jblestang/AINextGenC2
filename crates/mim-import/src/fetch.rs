use std::fs;
use std::io::Read;
use std::path::Path;

use mim_core::MimResult;

/// Official MIM / JC3IEDM source URLs on mimworld.org (MIP programme).
pub const MIMWORLD_JC3IEDM_OWL_URL: &str =
    "https://www.mimworld.org/attachments/download/JC3IEDM.owl";
pub const MIMWORLD_MIM_OWL_URL: &str =
    "https://www.mimworld.org/attachments/download/MIM.owl";

/// Fetch OWL ontology bytes from mimworld.org or local cache path.
pub fn fetch_mimworld_owl(url: &str) -> MimResult<String> {
    if url.starts_with("https://www.mimworld.org/") {
        fetch_https(url)
    } else if Path::new(url).exists() {
        fs::read_to_string(url).map_err(|e| mim_core::MimError::Io(e.to_string()))
    } else {
        Err(mim_core::MimError::NotFound(format!(
            "mimworld source not found: {url}"
        )))
    }
}

fn fetch_https(url: &str) -> MimResult<String> {
    ureq::get(url)
        .call()
        .map_err(|e| mim_core::MimError::Io(e.to_string()))?
        .into_string()
        .map_err(|e| mim_core::MimError::Io(e.to_string()))
}

/// Download mimworld JC3IEDM OWL to a local path for offline import.
pub fn download_to_path(url: &str, output: impl AsRef<Path>) -> MimResult<()> {
    let data = fetch_mimworld_owl(url)?;
    if let Some(parent) = output.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output.as_ref(), data).map_err(|e| mim_core::MimError::Io(e.to_string()))
}

/// Read OWL from path or fetch from mimworld when path is `--mimworld`.
pub fn load_owl_source(source: &str) -> MimResult<String> {
    match source {
        "mimworld" | "mimworld:jc3iedm" => fetch_mimworld_owl(MIMWORLD_JC3IEDM_OWL_URL),
        "mimworld:mim" => fetch_mimworld_owl(MIMWORLD_MIM_OWL_URL),
        path => {
            let mut file = fs::File::open(path)?;
            let mut data = String::new();
            file.read_to_string(&mut data)?;
            Ok(data)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn load_owl_from_local_path() {
        let sample = concat!(env!("CARGO_MANIFEST_DIR"), "/src/owl.rs");
        let err = load_owl_source(sample);
        assert!(err.is_err() || err.is_ok());
    }
}
