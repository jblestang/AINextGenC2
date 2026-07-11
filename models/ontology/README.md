# Bundled JC3IEDM OWL

Offline copy of the JC3IEDM OWL ontology used by `mim-import` when mimworld.org downloads are unavailable.

- **File:** `JC3IEDM.owl` (JC3IEDM v3.0, Vistology conversion)
- **Source:** [DISO compact distribution](https://github.com/city-artificial-intelligence/diso/tree/main/information-exchange/JC3IEDM)
- **Alternate mirror:** `https://raw.githubusercontent.com/city-artificial-intelligence/diso/main/information-exchange/JC3IEDM/JC3IEDM.owl`

Regenerate the full MIM manifest:

```bash
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

Or use the automatic fallback chain (`mimworld` → DISO mirror → bundled file):

```bash
cargo run -p mim-import -- --source mimworld \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```
