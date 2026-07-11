//! Cryptographic services for NATO metadata binding (NMBS) and ZTDF packaging.
//!
//! Provides a [`CryptoProvider`] trait with two backends:
//! - **ring** (default) — production-grade RustCrypto via `ring`
//! - **fips** — FIPS 140-3 validated module via `aws-lc-rs`
//!
//! Select at build time: `cargo build -p mim-crypto --features fips`

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::todo,
    clippy::unimplemented
)]

mod error;
mod hash;
mod keys;
mod pki;
mod provider;
mod runtime_pki;
mod symmetric;

#[cfg(all(feature = "ring-backend", not(feature = "fips")))]
mod ring_backend;

#[cfg(feature = "fips")]
mod fips_backend;

pub use error::{CryptoError, CryptoResult};
pub use hash::{sha256, sha256_base64};
pub use keys::{conformance_keypair, KeyPair, PublicKey, SigningKey, VerifyingKey};
pub use pki::{NmbKeyRing, NmbTrustStore};
pub use runtime_pki::{
    conformance_keys_enabled, load_key_ring, load_trust_store, ENV_CONFORMANCE_KEYS,
    ENV_KAS_SIGNING_KEY, ENV_NMB_SIGNING_KEY, ENV_NMB_TRUST,
};
pub use provider::{
    sign_nmb_binding, verify_nmb_binding, CryptoProvider, selected_provider, NMBS_ALGORITHM,
    NMBS_ALGORITHM_URI,
};
pub use symmetric::{AesGcmCiphertext, ContentEncryptionKey};
