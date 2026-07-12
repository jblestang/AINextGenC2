//! Runtime PKI selection — production PEM paths by default, conformance keys behind `MIM_CONFORMANCE_KEYS`.

use std::path::Path;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::conformance_keypair;
use crate::pki::{NmbKeyRing, NmbTrustStore};

/// Environment variable: set to `1` / `true` / `yes` to use bundled conformance keys.
pub const ENV_CONFORMANCE_KEYS: &str = "MIM_CONFORMANCE_KEYS";
/// Comma-separated SPKI PEM paths for inbound NMBS verification.
pub const ENV_NMB_TRUST: &str = "MIM_NMB_TRUST";
/// PKCS#8 PEM path for NMBS signing key.
pub const ENV_NMB_SIGNING_KEY: &str = "MIM_NMB_SIGNING_KEY";
/// PKCS#8 PEM path for KAS / ZTDF key-wrap signing key.
pub const ENV_KAS_SIGNING_KEY: &str = "MIM_KAS_SIGNING_KEY";

/// Returns true when lab conformance keys are explicitly enabled.
pub fn conformance_keys_enabled() -> bool {
    std::env::var(ENV_CONFORMANCE_KEYS)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

/// Load coalition NMBS/KAS key ring from environment or conformance fixture.
pub fn load_key_ring() -> CryptoResult<NmbKeyRing> {
    if conformance_keys_enabled() {
        return NmbKeyRing::conformance();
    }
    let nmb_path = std::env::var(ENV_NMB_SIGNING_KEY).map_err(|_| missing_env(ENV_NMB_SIGNING_KEY))?;
    let kas_path = std::env::var(ENV_KAS_SIGNING_KEY).map_err(|_| missing_env(ENV_KAS_SIGNING_KEY))?;
    NmbKeyRing::from_pkcs8_files(
        nmb_path,
        kas_path,
        "nmb-signing",
        "kas-signing",
    )
}

/// Load NMBS verifying trust store from environment or conformance fixture.
pub fn load_trust_store() -> CryptoResult<NmbTrustStore> {
    if conformance_keys_enabled() {
        let kp = conformance_keypair()?;
        return Ok(NmbTrustStore::from_verifying_keys([kp.verifying_key().clone()]));
    }
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
        "missing environment variable {name}; set production PEM paths or {ENV_CONFORMANCE_KEYS}=1 for lab conformance keys"
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
    fn conformance_flag_enables_fixture_key_ring() {
        let _guard = EnvGuard::with(&[(ENV_CONFORMANCE_KEYS, Some("1"))]);
        let ring = load_key_ring().expect("ring");
        assert_eq!(ring.nmb.signing.key_id, "nmb-conformance-key-1");
        assert_eq!(ring.kas.signing.key_id, "kas-conformance-key-1");
        assert_ne!(ring.nmb.signing.der(), ring.kas.signing.der());
    }

    #[test]
    fn conformance_flag_enables_fixture_trust_store() {
        let _guard = EnvGuard::with(&[(ENV_CONFORMANCE_KEYS, Some("1"))]);
        let store = load_trust_store().expect("trust");
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
        let _guard = EnvGuard::with(&[
            (ENV_CONFORMANCE_KEYS, None),
            (ENV_NMB_TRUST, Some(spki)),
        ]);
        let store = load_trust_store().expect("trust");
        assert_eq!(
            store.primary().expect("primary").key_id,
            "nmb-trust-0"
        );
    }

    #[test]
    fn missing_production_env_without_conformance_flag_errors() {
        let _guard = EnvGuard::with(&[(ENV_CONFORMANCE_KEYS, None), (ENV_NMB_TRUST, None)]);
        let err = load_trust_store().expect_err("missing env");
        assert!(err.to_string().contains(ENV_NMB_TRUST));
    }
}
