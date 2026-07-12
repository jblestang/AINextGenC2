//! Cryptographic services for NATO metadata binding (NMBS) and ZTDF packaging.
//!
//! Provides a [`CryptoProvider`] trait with three backends:
//! - **fips-validated** (default) — FIPS 140-3 validated AWS-LC module via `aws-lc-rs`
//! - **fips** — FIPS-capable AWS-LC (non-validated module) for lab builds
//! - **ring** — non-FIPS RustCrypto via `ring` (`--no-default-features --features ring-backend`)

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

#[cfg(all(feature = "ring-backend", not(any(feature = "fips", feature = "fips-validated"))))]
mod ring_backend;

#[cfg(any(feature = "fips", feature = "fips-validated"))]
mod fips_backend;

pub use error::{CryptoError, CryptoResult};
pub use hash::{sha256, sha256_base64, sha256_hex};
pub use keys::{
    conformance_key_ring, conformance_keypair, conformance_kas_keypair, KeyPair, PublicKey,
    SigningKey, VerifyingKey,
};
pub use pki::{NmbKeyRing, NmbTrustStore};
pub use runtime_pki::{
    load_key_ring, load_key_ring_for, load_trust_store, load_trust_store_for, PkiMode,
    ENV_CONFORMANCE_KEYS, ENV_KAS_SIGNING_KEY, ENV_NMB_SIGNING_KEY, ENV_NMB_TRUST,
};
pub use provider::{
    sign_nmb_binding, verify_nmb_binding, CryptoProvider, selected_provider, NMBS_ALGORITHM,
    NMBS_ALGORITHM_URI,
};
pub use symmetric::{AesGcmCiphertext, ContentEncryptionKey};
