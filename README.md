# AINextGenC2

Next-generation C4 information exchange base built on the **MIP Information Model (MIM)**.

> **Current status:** MIM, labeling, MIP4-IES, and ADatP conformance suites all report **100% FULLY COMPLIANT** (verified 2026-07-11). See **[docs/STATUS.md](docs/STATUS.md)** for precise numbers and operational readiness.

## MIM Rust Stack

A zero-panic, `Result`-driven Rust workspace implementing the semantic foundations required for full MIM 5.1 compliance:

| Crate | Responsibility |
|-------|----------------|
| `mim-core` | Semantic IDs (RFC 4122), MIM URIs, UN/CEFACT representation terms, nil-reason (`Nillable<T>`) |
| `mim-model` | Object/Action taxonomy, metadata, code lists, JSON manifest loader, model registry |
| `mim-runtime` | Instances with OIDs, validation, JSON/XML serialization |
| `mim-compliance` | Multi-dimensional compliance checker and reporting |
| `mim-labeling` | Format-agnostic confidentiality labels, policies, security domains |
| `mim-stanag4774` | STANAG 4774 (ADatP-4774) confidentiality metadata label codec |
| `mim-stanag4778` | STANAG 4778 (ADatP-4778) metadata binding mechanism (NMBS RSA-PSS) |
| `mim-crypto` | NMBS signatures, AES-256-GCM, RSA-OAEP key wrap, PKI (`NmbKeyRing`, `NmbTrustStore`) |
| `mim-spif` | XML-SPIF policy ingestion and validation (NATO, ACME, CAPCO-US, UK demo) |
| `mim-audit` | Hash-chained, NMBS-signable audit trail with SIEM export |
| `mim-ztdf` | ZTDF / OpenTDF encrypted ZIP packaging with NATO label assertions |
| `mim-dcs` | Data-centric security cross-domain guard and transfer |
| `mim-policy` | Policy plane: PIP, PAP/PRP, PDP, PEP + SPIF administration |
| `mim-transport` | MIP4-IES transport layer + STANAG 4778 REST envelope helpers |
| `mim-transport-http` | HTTPS/mTLS MIP4-IES server (Axum + rustls) |
| `mim-import` | OWL import from mimworld.org or local files |
| `mim-adatp-conformance` | NATO ADatP automated conformance test runner |
| `mim-labeling-compliance` | STANAG 4774/4778, ZTDF, DCS, SPIF, audit compliance (12 dimensions) |
| `ainextgenc2` | Integration library and CLI |

### NATO/STANAG documentation

- **[Precise status](docs/STATUS.md)** — compliance scores, manifest counts, deployment tiers, gaps
- **[System architecture — what it does](docs/NATO-STANAG-SYSTEM.md)** — subsystems, flows, deployment tiers
- **[Technology reference — how it does it](docs/NATO-STANAG-TECHNOLOGY.md)** — algorithms, crates, PKI, build flags, test matrix
- **[Remaining limitations](docs/REMAINING-STUBS-AND-LIMITATIONS.md)** — operational gaps and remediation priority
- **[MIP4-IES / FMN readiness](docs/MIP4-IES-FMN-READINESS.md)** — REST binding, scorecard, operational gaps

### Zero-panic policy

- All workspace crates `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, ...)]`
- `#![forbid(unsafe_code)]` on every crate
- `panic = "abort"` in dev and release profiles
- All fallible operations return `MimResult<T>`

### Compliance status

Run the compliance reports:

```bash
cargo run -p ainextgenc2              # MIM 5.1 (8 dimensions)
cargo run -p ainextgenc2 -- --labeling  # STANAG 4774/4778, ZTDF, DCS (12 dimensions)
cargo run -p ainextgenc2 -- --mip4      # MIP4-IES / FMN (140 checks, 7 dimensions)
cargo run -p ainextgenc2 -- --adatp     # NATO ADatP (39 test vectors)
```

All four suites report **100% FULLY COMPLIANT** with exit code 0 (verified 2026-07-11).

| Suite | Result |
|-------|--------|
| MIM 5.1 | 100% — 2,300 objects, 500 actions, 401 code lists, 3,740 elements |
| Labeling | 100% — 12/12 dimensions |
| MIP4-IES / FMN | 100% — 140/140 checks |
| ADatP | 100% — 39/39 tests |

Regenerate the full manifest from bundled JC3IEDM OWL (**932/932 OWL properties → 936 attributes**):

```bash
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

Or fetch from **mimworld.org** (falls back to DISO mirror, then bundled OWL):

```bash
cargo run -p mim-import -- --source mimworld \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

Or from a local OWL file:

```bash
cargo run -p mim-import -- --owl /path/to/JC3IEDM.owl \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

MIM 5.1 scale targets (met by bundled manifest):

- 2,300 object types
- 500 action types
- 400 code lists (401 loaded)
- 936 attribute elements (932 OWL-derived + 4 core seed merge)

### Exit codes

- `0` — fully compliant for the requested suite
- `1` — runtime error
- `2` — not yet compliant (partial implementation)


```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

### Architecture

```
models/mim-core-5.1.json  →  mim-model (registry)  →  mim-runtime (instances)
                                        ↓                        ↓
                              mim-compliance (report)    mim-transport (MIP4-IES REST)
                                                                   ↓ PEP
                              mim-labeling → mim-policy (PIP/PDP) → mim-dcs (cross-domain PEP)
                                        ↑ PAP/PRP
```

To reach 100% MIM compliance, load `models/mim-full-5.1.json` (bundled; regenerated via `mim-import`). Custom manifests can be loaded via `MimStack::load_path()`.

### Bundled scenarios

| Scenario | Command / API | Purpose |
|----------|---------------|---------|
| Air defense radar | `cargo run --example air_defense_radar` | Sensor → MIM tracks/targets |
| DCS cross-domain | `cargo run --example dcs_cross_domain` | Label + NMBS + ZTDF + guard downgrade |
| MIP4-IES exchange | `cargo run --example mip4_ies_exchange` | PEP-gated broker CRUD |
| Allied sensor retrieval | `AlliedSensorRetrievalScenario::demo()` | Coalition sync; national-only tracks hidden |
| SITAC simulator | `cargo run --example sitac_simulator` | 4 radars + FCS/4 TELs; national C2; long-range coalition share |
| Transport exchange | `TransportExchangeScenario::demo()` | Secured publish + filter |

### Air defense radar example

Demonstrates a `SiteAirDefenceRadar` sensor producing MIM `TrackIdentifier` and `Target` instances for each detection, linked via associations (`producedTrack`, `reportedBy`, `trackIdentifier`):

```bash
cargo run --example air_defense_radar
```

The example prints two demo tracks (HOSTILE-1, UNKNOWN-2) and the full MIM exchange JSON. Use the scenario API in library code:

```rust
use ainextgenc2::{AirDefenseRadarScenario, MimStack};

let stack = MimStack::load()?;
let output = AirDefenseRadarScenario::demo().run(&stack)?;
println!("{}", output.exchange_json);
```

### DCS cross-domain labeling

Labels MIM exchanges with **STANAG 4774** confidentiality metadata, binds labels via **STANAG 4778** assertion profiles, packages in **ZTDF** manifests, and transfers across security domains through a DCS guard (allow / deny / downgrade):

```bash
cargo run --example dcs_cross_domain
```

The demo downgrades a SECRET/REL USA,GBR radar exchange from a high-side domain to RESTRICTED on the low side, emitting STANAG 4774 XML and a ZTDF manifest.

> **Note:** NATO standard references are STANAG **4774** (label syntax) and STANAG **4778** (binding). These are commonly grouped with ZTDF (ACP-240 / OpenTDF) for DCS Level 1–3 interoperability.

### MIP4-IES transport layer

Publishes MIM instances through the MIP4-IES exchange service interface (PutObject, GetByOID, GetByFilter, DeleteObject) with REST binding paths:

```bash
cargo run --example mip4_ies_exchange
```

The demo publishes the air defense radar store (5 instances) to a PEP-gated exchange broker, queries targets by filter, and serializes the active exchange payload. Instances are labeled SECRET/REL USA,GBR; the operator must hold sufficient clearance or PutObject is denied.

### Policy plane (PIP / PAP / PDP / PEP)

| Component | Crate | Role |
|-----------|-------|------|
| PIP | `mim-policy` | Assembles subject, resource, and environment attributes |
| PAP / PRP | `mim-policy` | Authors and stores domain + cross-domain policies |
| PDP | `mim-policy` | Evaluates permit / deny / downgrade decisions |
| PEP | `mim-policy` + `mim-transport` / `mim-dcs` | Enforces decisions at transport and cross-domain boundaries |

## License

MIT OR Apache-2.0
