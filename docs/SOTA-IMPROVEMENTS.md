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

## STANAG 4778

- **Optional NMBS:** `embedded_with_nmb()`, `detached_with_nmb()`, etc.
- **Detached labels:** `mim-stanag4778/src/detached.rs` — `FileDetachedLabelResolver`, `verify_detached_label()`
- **Verify:** NMBS when assertion present on any profile; detached URI fetch + label match

## MIM full handling

- **OWL:** `ObjectProperty` / `DatatypeProperty` with domain, range, labels; imported as manifest attributes
- **Metadata taxonomy:** Reporter, Observer, OperationalAppraisal, ValidityPeriod, SecurityClassification in `mim-core-5.1.json`
- **Full manifest load:** merges metadata from core seed when loading `mim-full-5.1.json`
- **Compliance:** metadata dimension requires 5 subtypes + element coverage

## Verification

```bash
cargo test --workspace
cargo test -p mim-spif
cargo test -p mim-dcs
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --adatp
```
