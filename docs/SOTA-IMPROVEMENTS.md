# SOTA Improvements (SPIF, DCS, STANAG, MIM)

Summary of state-of-the-art hardening delivered on branch `cursor/sota-spif-dcs-stanag-mim-0965`.

## SPIF — XSD validation

- **Schemas:** `crates/mim-spif/schemas/spif-iso29008-2011.xsd` (ISO 29008:2011 fixtures) + vendored `xmlspif.xsd` (XML-SPIF 2.x)
- **Module:** `mim-spif/src/xsd.rs` — validates via `xmllint --schema` with pure-Rust structural fallback
- **Parser:** XSD gate before semantic parse; extracts `versioninfo` into `SpifVersionInfo`
- **API:** `validate_spif_xsd()`, `SpifSchemaProfile::detect()`

## DCS — configurable (not hardcoded)

- **Config file:** `config/dcs-coalition.toml` — domains, cross-domain rules, SPIF paths, downgrade policy
- **Module:** `mim-dcs/src/config.rs` — `DcsConfig::load_path()`, `build_guard()`, path resolution from workspace root
- **API:** `CrossDomainGuard::from_config()`, `from_config_file()`
- **Downgrade:** `mim-policy/src/downgrade.rs` — category-aware releasability intersection (not classification-only)
- **SPIF admin:** `with_spif_registry()` builds domains from config/SPIF (no preset overlay); NATO-only releasability sync

## STANAG 4774

- **Extended label model:** `alternative_labels`, `colour`, `marking_data`
- **XML:** serialize/deserialize `alternativeConfidentialityLabel`, `Colour`, `MarkingData`
- **XSD:** `crates/mim-stanag4774/schemas/stanag4774-label.xsd` + `validate_stanag4774_xsd()`
- **Codec:** `deserialize_with_options(..., validate_xsd)` gates XML labels on schema validation

## STANAG 4778

- **Optional NMBS:** `embedded_with_nmb()`, `detached_with_nmb()`, etc.
- **Detached labels:** `mim-stanag4778/src/detached.rs` — `FileDetachedLabelResolver`, `verify_detached_label()`
- **Verify:** NMBS when assertion present on any profile; detached URI fetch + label match

## MIM full handling

- **OWL:** `ObjectProperty` / `DatatypeProperty` with domain, range, labels; URI normalization for JC3IEDM
- **Metadata taxonomy:** Reporter, Observer, OperationalAppraisal, ValidityPeriod, SecurityClassification in `mim-core-5.1.json`
- **Full manifest:** `models/mim-full-5.1.json` regenerated from bundled `models/ontology/JC3IEDM.owl` (**820 attributes**)
- **Import fallback:** mimworld → DISO mirror → bundled OWL (`--source bundled:jc3iedm`)
- **Compliance:** metadata dimension requires 5 subtypes + element coverage

## Follow-up deliverables

- STANAG 4774 label XSD validation
- Regenerated full manifest with OWL property import at scale
- Bundled JC3IEDM OWL for offline/reproducible import
- FIPS build on Rust 1.85 (`rust-toolchain.toml`, `mim-crypto` FIPS fix)
- Updated [REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md)

## Verification

```bash
cargo test --workspace
cargo test -p mim-spif
cargo test -p mim-stanag4774
cargo test -p mim-crypto --features fips
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --adatp
```
