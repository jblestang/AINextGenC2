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
| `ainextgenc2` | Integration library and CLI |

### Zero-panic policy

- All workspace crates `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, ...)]`
- `#![forbid(unsafe_code)]` on every crate
- `panic = "abort"` in dev and release profiles
- All fallible operations return `MimResult<T>`

### Compliance status

Run the compliance report:

```bash
cargo run -p ainextgenc2
# or with a custom manifest:
cargo run -p ainextgenc2 -- /path/to/mim-manifest.json
```

The bundled seed manifest (`models/mim-core-5.1.json`) implements foundational MIM concepts from public documentation (Object/Action/Metadata taxonomy, MilitaryConvoy attributes, UnitRangeCode, nil-reason, metadata). **Full MIM 5.1 compliance** requires importing the complete model from [mimworld.org](https://www.mimworld.org) (member access) as JSON manifest, OWL, or XSD.

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

## License

MIT OR Apache-2.0
