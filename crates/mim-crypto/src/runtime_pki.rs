//! Runtime PKI selection — explicit lab vs production modes; production PEM paths from environment.

use std::path::Path;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{conformance_key_ring, conformance_keypair};
use crate::pki::{NmbKeyRing, NmbTrustStore};

/// How signing keys and trust material are sourced at runtime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PkiMode {
    /// Bundled conformance fixtures (tests, lab demos, CI).
    Lab,
    /// Production PEM paths from environment variables.
    #[default]
    Production,
}

/// Comma-separated SPKI PEM paths for inbound NMBS verification.
pub const ENV_NMB_TRUST: &str = "MIM_NMB_TRUST";
/// PKCS#8 PEM path for NMBS signing key.
pub const ENV_NMB_SIGNING_KEY: &str = "MIM_NMB_SIGNING_KEY";
/// PKCS#8 PEM path for KAS / ZTDF key-wrap signing key.
pub const ENV_KAS_SIGNING_KEY: &str = "MIM_KAS_SIGNING_KEY";

/// Deprecated: prefer [`PkiMode::Lab`] via [`load_key_ring_for`].
pub const ENV_CONFORMANCE_KEYS: &str = "MIM_CONFORMANCE_KEYS";

/// Load coalition NMBS/KAS key ring for the given mode.
pub fn load_key_ring_for(mode: PkiMode) -> CryptoResult<NmbKeyRing> {
    match mode {
        PkiMode::Lab => conformance_key_ring(),
        PkiMode::Production => load_production_key_ring(),
    }
}

/// Load NMBS verifying trust store for the given mode.
pub fn load_trust_store_for(mode: PkiMode) -> CryptoResult<NmbTrustStore> {
    match mode {
        PkiMode::Lab => {
            let kp = conformance_keypair()?;
            Ok(NmbTrustStore::from_verifying_keys([kp.verifying_key().clone()]))
        }
        PkiMode::Production => load_production_trust_store(),
    }
}

/// Load production coalition key ring from `MIM_NMB_SIGNING_KEY` / `MIM_KAS_SIGNING_KEY`.
pub fn load_key_ring() -> CryptoResult<NmbKeyRing> {
    load_key_ring_for(PkiMode::Production)
}

/// Load production NMBS trust store from `MIM_NMB_TRUST`.
pub fn load_trust_store() -> CryptoResult<NmbTrustStore> {
    load_trust_store_for(PkiMode::Production)
}

fn load_production_key_ring() -> CryptoResult<NmbKeyRing> {
    let nmb_path =
        std::env::var(ENV_NMB_SIGNING_KEY).map_err(|_| missing_env(ENV_NMB_SIGNING_KEY))?;
    let kas_path =
        std::env::var(ENV_KAS_SIGNING_KEY).map_err(|_| missing_env(ENV_KAS_SIGNING_KEY))?;
    NmbKeyRing::from_pkcs8_files(nmb_path, kas_path, "nmb-signing", "kas-signing")
}

fn load_production_trust_store() -> CryptoResult<NmbTrustStore> {
    let trust_paths = std::env::var(ENV_NMB_TRUST).map_err(|_| missing_env(ENV_NMB_TRUST))?;
    let paths: Vec<&Path> = trust_paths
        .split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(Path::new)
        .collect();
    if paths.is_empty() {
        return Err(CryptoError::InvalidKey(format!(
            "{ENV_NMB_TRUST} must list at least one SPKI PEM path"
        )));
    }
    NmbTrustStore::from_spki_pem_files(paths)
}

fn missing_env(name: &str) -> CryptoError {
    CryptoError::InvalidKey(format!(
        "missing environment variable {name}; configure production PEM paths or use PkiMode::Lab"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        vars: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn with(vars: &[(&'static str, Option<&str>)]) -> Self {
            let lock = ENV_LOCK.lock().expect("env lock");
            let mut saved = Vec::new();
            for (key, value) in vars {
                saved.push((*key, std::env::var(key).ok()));
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            Self {
                _lock: lock,
                vars: saved,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.vars.drain(..) {
                match value {
                    Some(previous) => std::env::set_var(key, previous),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn lab_mode_loads_fixture_key_ring() {
        let ring = load_key_ring_for(PkiMode::Lab).expect("ring");
        assert_eq!(ring.nmb.signing.key_id, "nmb-conformance-key-1");
        assert_eq!(ring.kas.signing.key_id, "kas-conformance-key-1");
        assert_ne!(ring.nmb.signing.der(), ring.kas.signing.der());
    }

    #[test]
    fn lab_mode_loads_fixture_trust_store() {
        let store = load_trust_store_for(PkiMode::Lab).expect("trust");
        assert_eq!(
            store.primary().expect("primary").key_id,
            "nmb-conformance-key-1"
        );
    }

    #[test]
    fn production_trust_store_from_spki_env() {
        let spki = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/nmb-conformance-rsa.pub.pem"
        );
        let _guard = EnvGuard::with(&[(ENV_NMB_TRUST, Some(spki))]);
        let store = load_trust_store_for(PkiMode::Production).expect("trust");
        assert_eq!(
            store.primary().expect("primary").key_id,
            "nmb-trust-0"
        );
    }

    #[test]
    fn missing_production_env_errors() {
        let _guard = EnvGuard::with(&[(ENV_NMB_TRUST, None)]);
        let err = load_trust_store_for(PkiMode::Production).expect_err("missing env");
        assert!(err.to_string().contains(ENV_NMB_TRUST));
    }
}
