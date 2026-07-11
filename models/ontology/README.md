# Bundled JC3IEDM OWL

Offline copy of the JC3IEDM OWL ontology used by `mim-import` when mimworld.org downloads are unavailable.

| Field | Value |
|-------|-------|
| **File** | `JC3IEDM.owl` (JC3IEDM v3.0, Vistology conversion) |
| **Source** | [DISO compact distribution](https://github.com/city-artificial-intelligence/diso/tree/main/information-exchange/JC3IEDM) |
| **Mirror** | `https://raw.githubusercontent.com/city-artificial-intelligence/diso/main/information-exchange/JC3IEDM/JC3IEDM.owl` |

## Regenerate the full MIM manifest

Bundled source (offline, reproducible — recommended):

```bash
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

Automatic fallback chain (`mimworld` → DISO mirror → bundled file):

```bash
cargo run -p mim-import -- --source mimworld \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

## Expected import output

When import completes successfully, the CLI prints manifest counts and OWL attribute coverage:

```
objects=2300 actions=500 code_lists=401 attributes=936 elements=3740
owl_properties=932 xml_tag_lines=1748 with_domain=932 imported=932 skipped=0
coverage=100.0% target=100% (MET)
```

| Metric | Value |
|--------|------:|
| Declared OWL properties | 932 |
| Properties with resolved domain | 932 |
| Properties imported as MIM attributes | 932 |
| Skipped | 0 |
| Manifest attributes (after core seed merge) | 936 |
| Attribute coverage (declared properties) | **100%** |
| XML property tag lines (diagnostic only) | 1,748 |

The four extra manifest attributes come from merging `models/mim-core-5.1.json` metadata seed (932 OWL-derived + 4 core).

## Import pipeline

1. Parse all `ObjectProperty` / `DatatypeProperty` declarations (including self-closing inverse stubs)
2. `resolve_property_domains()` — iterative `inverseOf` + `subPropertyOf` until stable
3. `ensure_property_domains_in_taxonomy()` — domain classes added to taxonomy
4. `import_owl_attributes()` — ancestor-walk domain resolution; default target coverage **100%**

**Not imported:** OWL reasoning, SHACL, or authoritative MIM 5.1 OWL (mimworld unavailable; bundled JC3IEDM v3.0 used).

## Related documentation

- [docs/STATUS.md](../../docs/STATUS.md) — precise compliance and manifest status
- [docs/NATO-STANAG-TECHNOLOGY.md](../../docs/NATO-STANAG-TECHNOLOGY.md) — `mim-import` crate reference
