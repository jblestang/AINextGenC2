# SOTA Improvements (SPIF, DCS, STANAG, MIM)

Summary of state-of-the-art hardening delivered across branches `cursor/sota-spif-dcs-stanag-mim-0965` and `cursor/owl-attribute-import-loop-bb0a` (merged to `main`).

**Current status:** see [STATUS.md](./STATUS.md).

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

- **Extended label model:** `alternative_labels`, `colour`, `marking_data`, handling caveats
- **XML:** serialize/deserialize `alternativeConfidentialityLabel`, `Colour`, `MarkingData`
- **XSD:** `crates/mim-stanag4774/schemas/stanag4774-label.xsd` + `validate_stanag4774_xsd()`
- **Codec:** `deserialize_with_options(..., validate_xsd)` gates XML labels on schema validation

## STANAG 4778

- **Optional NMBS:** `embedded_with_nmb()`, `detached_with_nmb()`, etc.
- **Detached labels:** `mim-stanag4778/src/detached.rs` — `FileDetachedLabelResolver`, `verify_detached_label()`
- **Verify:** NMBS when assertion present on any profile; detached URI fetch + label match

## MIM full handling — OWL attribute import loop

- **OWL parser:** `ObjectProperty` / `DatatypeProperty` including self-closing inverse stubs; `inverseOf` + `subPropertyOf`
- **Domain resolution:** `resolve_property_domains()` iterative loop until stable
- **Taxonomy:** `ensure_property_domains_in_taxonomy()` + `ancestors_of()` domain walk
- **Import loop:** `import_owl_attributes()` — 100% of 932 declared JC3IEDM properties
- **Metadata taxonomy:** Reporter, Observer, OperationalAppraisal, ValidityPeriod, SecurityClassification in `mim-core-5.1.json`
- **Full manifest:** `models/mim-full-5.1.json` — **936 attributes**, 3,740 elements, MIM 5.1 scale targets met
- **Import fallback:** mimworld → DISO mirror → bundled OWL (`--source bundled:jc3iedm`)
- **Coverage reporting:** `ImportReport` with `owl_properties_total`, `owl_attribute_coverage_ratio` (target 100%)

## MIP4-IES / FMN

- **Transport:** CRUD, XPath filter subset, pagination, replication sync, file persistence
- **Conformance:** `mim-mip4-conformance` — **140/140 checks pass** (`ainextgenc2 --mip4`)

## Compliance (all pass at 100%)

| Suite | Result |
|-------|--------|
| MIM 5.1 (`ainextgenc2`) | 100% — 8/8 dimensions |
| Labeling (`--labeling`) | 100% — 12/12 dimensions |
| MIP4-IES (`--mip4`) | 100% — 140/140 checks |
| ADatP (`--adatp`) | 100% — 39/39 tests |

## Verification

```bash
cargo test --workspace
cargo test -p mim-spif
cargo test -p mim-stanag4774
cargo test -p mim-crypto --features fips
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
cargo run -p ainextgenc2
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --mip4
cargo run -p ainextgenc2 -- --adatp
```

## Remaining work

See [REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md) — primarily operational pilot items (PKI, LDAP/SAML PIP, mission-aware PDP, live HTTPS E2E, KAS/ABAC).
