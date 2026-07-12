# AINextGenC2 NATO/STANAG Technology Reference

This document describes **how the stack implements** NATO/STANAG requirements — crates, algorithms, protocols, and build options.

**Precise status:** [STATUS.md](./STATUS.md)

## Crate map

| Crate | Technology role |
|-------|-----------------|
| `mim-crypto` | Cryptographic boundary — NMBS, ZTDF encryption, PKI loading |
| `mim-spif` | XML-SPIF parser and label validator |
| `mim-stanag4774` | STANAG 4774 label codec (XML + JSON-structured) |
| `mim-stanag4778` | STANAG 4778 binding profiles + REST/SMTP envelopes |
| `mim-ztdf` | ZTDF ZIP packaging (AES-256-GCM + manifest) |
| `mim-audit` | Hash-chained, NMBS-signable audit envelopes |
| `mim-policy` | XACML-style PIP/PAP/PDP/PEP + SPIF administration |
| `mim-dcs` | Cross-domain guard and transfer orchestration |
| `mim-transport` | MIP4-IES REST broker + STANAG 4778 envelope helpers |
| `mim-transport-http` | Axum + rustls HTTPS/mTLS server |
| `mim-import` | mimworld.org OWL fetch + manifest import |
| `mim-labeling-compliance` | 12-dimension automated compliance checker |
| `mim-adatp-conformance` | NATO ADatP test vector runner |

## Cryptography (`mim-crypto`)

### Algorithms

| Function | Algorithm | Standard |
|----------|-----------|----------|
| NMBS binding sign/verify | RSA-PSS with SHA-256 | ADatP-4778 NMBS |
| Payload / metadata digest | SHA-256 (Base64) | STANAG 4778 integrity |
| ZTDF payload encryption | AES-256-GCM | OpenTDF / ACP-240 |
| ZTDF key wrap | RSA-OAEP with SHA-256 | OpenTDF split encryption |

### NMBS message format

Signing canonicalizes as:

```
message = UTF-8(label_xml) || 0x7C || ASCII(payload_digest_base64)
signature = RSA-PSS-SHA256(message)
```

Assertion bindings store `signed_label_xml` — the exact bytes signed — to survive JSON/ZTDF manifest round-trips without XML re-serialization drift.

### Provider backends

| Feature flag | Backend | AES-GCM / SHA-256 | RSA (NMBS/KAS) |
|--------------|---------|-------------------|----------------|
| `fips-validated` (default) | `aws-lc-rs/fips` | FIPS 140-3 module | rsa crate* |
| `fips` | `aws-lc-rs` (non-FIPS build) | AWS-LC | rsa crate |
| `ring-backend` | `ring` + `rsa` crate | ring | rsa crate |

\* RSA key operations remain in the `rsa` Rust crate outside the FIPS module boundary. For accredited deployments, place RSA operations in an approved HSM/KMS and supply keys via PKCS#8/SPKI through the PKI API below.

Build examples:

```bash
# Default — FIPS 140-3 validated module (requires Rust ≥ 1.85, cmake, Go)
cargo build -p mim-crypto

# AWS-LC module without validated boundary (faster lab builds)
cargo build -p mim-crypto --no-default-features --features fips

# Non-FIPS development only
cargo build -p mim-crypto --no-default-features --features ring-backend
```

### Production PKI

```rust
use mim_crypto::{NmbKeyRing, NmbTrustStore};

// Load operator NMBS + KAS keys from PKCS#8 PEM
let ring = NmbKeyRing::from_pkcs8_files(
    "/etc/mim/nmb-signing.pk8",
    "/etc/mim/kas-signing.pk8",
    "nmb-prod-1",
    "kas-prod-1",
)?;

// Load coalition verifying keys from SPKI PEM
let trust = NmbTrustStore::from_spki_pem_files(["/etc/mim/nmb-trust.pem"])?;
```

Lab/conformance mode uses `NmbKeyRing::conformance()` with separate fixtures: `nmb-conformance-rsa.pk8` (NMBS, `nmb-conformance-key-1`) and `kas-conformance-rsa.pk8` (KAS, `kas-conformance-key-1`).

## SPIF (`mim-spif`)

- **Parser:** `quick-xml` streaming parser for XML-SPIF policy documents
- **Policies shipped:** NATO 4774 reference, ACME ADatP-4774.1, CAPCO-US demo, UK DEMO demo
- **Validation:** classification allow-list, category value constraints, SPIF validation rules (e.g. ACME CONFIDENTIAL requires Releasable To MOCK/PHONY)

SPIF integrates with policy administration:

```rust
use mim_policy::PolicyAdministrationPoint;
use mim_spif::SpifRegistry;

let pap = PolicyAdministrationPoint::with_spif_registry(SpifRegistry::with_defaults())?;
// Domain releasability in PRP now reflects SPIF "Releasable To" categories
```

Cross-domain guard from SPIF:

```rust
use mim_dcs::CrossDomainGuard;

let guard = CrossDomainGuard::from_spif_registry(SpifRegistry::with_defaults())?;
```

## STANAG 4778 binding profiles (`mim-stanag4778`)

Implemented in Rust with `serde` JSON serialization:

- **Digest integrity:** SHA-256 over payload bytes on all profiles
- **Assertion profiles:** delegate to `mim-crypto::sign_nmb_binding` / `verify_nmb_binding`
- **SPIF gate:** `SpifValidator::validate_label` at assertion bind time

REST envelope fields (`RestEnvelope`):

| Field | Content |
|-------|---------|
| `originatorConfidentialityLabel` | STANAG 4774 XML |
| `payloadDigest` | SHA-256 Base64 of payload |
| `payload` | MIM JSON string |
| `assertion` | NMBS `AssertionBinding` |

HTTP header `X-NATO-Confidentiality-Label` must match `originatorConfidentialityLabel`.

## ZTDF (`mim-ztdf`)

ZIP layout:

```
manifest.json   # tdf_spec_version 1.0.0, encryption_information, assertions[]
0.payload       # IV || ciphertext || tag (AES-256-GCM)
```

Manifest assertion `nato-label-1` carries JSON-structured STANAG 4774 label plus `signedLabelXml` for NMBS verification. CEK is wrapped with KAS public key (RSA-OAEP-SHA256).

## Audit trail (`mim-audit`)

Each record is wrapped in an `AuditEnvelope`:

| Field | Purpose |
|-------|---------|
| `previousHash` | Chain link (starts at `GENESIS`) |
| `recordHash` | SHA-256(`previousHash \| JSON(record)`) |
| `signature` | Optional NMBS over `audit-record \| recordHash` |

```rust
use mim_audit::AuditLog;

let audit = AuditLog::memory().with_signing_key(nmb_signing_key);
audit.record(record)?;
audit.verify_chain()?;
let siem = audit.export_siem()?;
```

File sink writes append-only JSON lines via `FileAuditSink::open(path)`.

## MIP4-IES transport

### REST routes (`mim-transport::rest`)

| Method | Path | Operation |
|--------|------|-----------|
| PUT | `/mip4-ies/v1/objects` | PutObject |
| GET | `/mip4-ies/v1/objects/{oid}` | GetByOID |
| GET | `/mip4-ies/v1/objects` | GetByFilter |
| DELETE | `/mip4-ies/v1/objects/{oid}` | DeleteObject |

### Envelope helpers (`mim-transport::envelope`)

```rust
use mim_transport::envelope::{wrap_put_object, unwrap_put_object};

let envelope = wrap_put_object(&label, &put_request, &nmb_signing_key)?;
let request = unwrap_put_object(&envelope, &nmb_verifying_key)?;
```

### HTTPS server (`mim-transport-http`)

| Route | Method | Operation |
|-------|--------|-----------|
| `/mip4-ies/v1/objects` | PUT | PutObject (STANAG 4778 envelope) |
| `/mip4-ies/v1/objects/:oid` | GET | GetByOID |
| `/mip4-ies/v1/objects` | GET | GetByFilter (`?filter=//Class…` or legacy query params) |
| `/mip4-ies/v1/objects/:oid` | DELETE | DeleteObject |

Use `exchange_router()` for embedded HTTP stacks; `HttpExchangeServer` serves the same routes over TLS/mTLS.

See [MIP4-IES-FMN-READINESS.md](./MIP4-IES-FMN-READINESS.md).

```rust
use mim_transport_http::{HttpExchangeConfig, HttpExchangeServer};

let config = HttpExchangeConfig {
    trust_store: NmbTrustStore::from_spki_pem_files(["/etc/mim/trust.pem"])?,
};
let server = HttpExchangeServer::new(addr, tls_identity)
    .with_config(config)
    .with_client_ca(include_bytes!("/etc/mim/client-ca.pem"))?; // optional mTLS
```

The server selects the verifying key by NMBS `keyId` from the REST envelope assertion — not a hardcoded conformance key.

## Policy plane (`mim-policy`)

XACML-inspired separation:

| Component | Rust type | Responsibility |
|-----------|-----------|----------------|
| PIP | `PolicyInformationPoint` | Assemble subject/resource/environment context |
| PRP | `PolicyStore` | Store domains, cross-domain rules, SPIF policies |
| PAP | `PolicyAdministrationPoint` | Author/register policies and SPIF XML |
| PDP | `PolicyDecisionPoint` | Evaluate permit/deny/downgrade |
| PEP | `PolicyEnforcementPoint` | Enforce at transport/DCS boundary; optional audit |

PEP audit integration:

```rust
use mim_audit::AuditLog;
use mim_policy::PolicyEnforcementPoint;

let pep = PolicyEnforcementPoint::from_preset_high_to_low()
    .with_audit(AuditLog::memory());
```

## MIM import (`mim-import`)

```bash
# Bundled JC3IEDM (offline, reproducible) — recommended
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json

# Authoritative mimworld JC3IEDM (falls back to DISO mirror, then bundled OWL)
cargo run -p mim-import -- --source mimworld \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json

# Local OWL file
cargo run -p mim-import -- --owl /path/to/JC3IEDM.owl --output models/mim-full-5.1.json
```

Import pipeline (`OwlImporter`):

| Step | Function | Result |
|------|----------|--------|
| Parse OWL | `OwlModel::parse_xml` | 932 declared properties |
| Resolve domains | `resolve_property_domains()` | `inverseOf` + `subPropertyOf` loop |
| Build taxonomy | class import + `ensure_property_domains_in_taxonomy` | 2,300 objects, 500 actions |
| Import attributes | `import_owl_attributes()` | 932/932 imported (100%) |
| Merge seed | `mim-core-5.1.json` | +4 metadata attributes → 936 total |

CLI reports: `owl_properties`, `xml_tag_lines` (diagnostic), `coverage`, `target`.

Set `authoritative_mimworld` to skip synthetic taxonomy padding.

## Language and quality constraints

- **Rust edition 2021**, MSRV **1.85** (`rust-toolchain.toml`); required for `mim-crypto --features fips`
- **Zero-panic policy:** `#![deny(clippy::unwrap_used, ...)]`, `#![forbid(unsafe_code)]`
- **Serialization:** `serde` + `serde_json` throughout wire formats
- **XML:** `quick-xml` for STANAG 4774 XML and SPIF

## Security boundaries

```mermaid
flowchart LR
  subgraph unclassified [Application Layer]
    APP[ainextgenc2 / brokers]
  end

  subgraph crypto [Crypto Boundary - mim-crypto]
    NMBS[NMBS RSA-PSS]
    AES[AES-256-GCM]
    HASH[SHA-256]
  end

  subgraph pki [PKI - operator provided]
    HSM[HSM / PEM keys]
  end

  APP --> NMBS
  APP --> AES
  HSM --> NMBS
  HSM --> AES
```

## Testing matrix

| Suite | Command | Current result |
|-------|---------|----------------|
| MIM 5.1 compliance | `cargo run -p ainextgenc2` | **100%** — 8/8 dimensions |
| Labeling compliance | `cargo run -p ainextgenc2 -- --labeling` | **100%** — 12/12 dimensions |
| MIP4-IES conformance | `cargo run -p ainextgenc2 -- --mip4` | **100%** — 140/140 checks |
| ADatP conformance | `cargo run -p ainextgenc2 -- --adatp` | **100%** — 39/39 tests |
| ADatP unit tests | `cargo test -p mim-adatp-conformance` | Pass |
| Labeling unit tests | `cargo test -p mim-labeling-compliance` | Pass |
| DCS scenario | `cargo test -p ainextgenc2 dcs_scenario` | Pass |
| OWL import | `cargo test -p mim-import` | Pass — 932 properties |
| HTTP envelope | `cargo test -p mim-transport-http handle_put` | Pass |
| Crypto / PKI | `cargo test -p mim-crypto` | Pass |
| Audit chain | `cargo test -p mim-audit` | Pass |
| SPIF admin | `cargo test -p mim-policy spif` | Pass |

## Related documents

- [STATUS.md](./STATUS.md) — precise compliance numbers and operational readiness
- [NATO-STANAG-SYSTEM.md](./NATO-STANAG-SYSTEM.md) — system-level architecture and flows
- [REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md) — operational gaps
- [../README.md](../README.md) — workspace overview and quick start
