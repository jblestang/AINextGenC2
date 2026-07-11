# AINextGenC2

Next-generation C4 information exchange base built on the **MIP Information Model (MIM)**.

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
| `mim-stanag4778` | STANAG 4778 (ADatP-4778) metadata binding mechanism |
| `mim-ztdf` | ZTDF / OpenTDF manifest packaging with NATO label assertions |
| `mim-dcs` | Data-centric security cross-domain guard and transfer |
| `mim-labeling-compliance` | STANAG 4774/4778, ZTDF, and DCS compliance checker |
| `ainextgenc2` | Integration library and CLI |

### Zero-panic policy

- All workspace crates `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, ...)]`
- `#![forbid(unsafe_code)]` on every crate
- `panic = "abort"` in dev and release profiles
- All fallible operations return `MimResult<T>`

### Compliance status

Run the compliance report (MIM + labeling):

```bash
cargo run -p ainextgenc2
# labeling-only report:
cargo run -p ainextgenc2 -- --labeling
# or with a custom manifest:
cargo run -p ainextgenc2 -- /path/to/mim-manifest.json
```

Both MIM 5.1 and labeling (STANAG 4774/4778, ZTDF, DCS) must be fully compliant for exit code 0.

The workspace loads `models/mim-full-5.1.json` when present (generated from JC3IEDM OWL + MIM core seed). Regenerate with:

```bash
curl -sL -o /tmp/jc3iedm.owl \
  https://raw.githubusercontent.com/city-artificial-intelligence/diso/main/information-exchange/JC3IEDM/JC3IEDM.owl
cargo run -p mim-import -- --owl /tmp/jc3iedm.owl \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

For authoritative MIM 5.1+ semantics, replace the import source with official mimworld.org OWL/XSD exports when available.

Targets for full compliance (MIM 5.1 scale):

- ~2,300 object types
- ~500 action types
- ~400 code lists

### Exit codes

- `0` — fully MIM compliant
- `1` — runtime error
- `2` — not yet compliant (partial implementation)


```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

### Architecture

```
models/mim-core-5.1.json  →  mim-model (registry)  →  mim-runtime (instances)
                                        ↓
                              mim-compliance (report)
```

To reach 100% coverage, export the official MIM 5.1+ OWL/XSD products to the manifest format and load via `MimStack::load_path()`.

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

## License

MIT OR Apache-2.0
