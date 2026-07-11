# AINextGenC2 — Precise Status

Last verified: **2026-07-11** (workspace on `main`, commit after OWL attribute import merge).

Run the commands in [Verification](#verification) to reproduce these numbers locally.

---

## Compliance summary

| Suite | Command | Result | Detail |
|-------|---------|--------|--------|
| **MIM 5.1** | `cargo run -p ainextgenc2` | **100% — FULLY COMPLIANT** | 8/8 dimensions; exit code 0 |
| **Labeling** | `cargo run -p ainextgenc2 -- --labeling` | **100% — FULLY COMPLIANT** | 12/12 STANAG 4774/4778, ZTDF, DCS, SPIF, audit dimensions |
| **MIP4-IES / FMN** | `cargo run -p ainextgenc2 -- --mip4` | **100% — FULLY COMPLIANT** | 140/140 checks; all 7 dimensions ≥ 95% threshold |
| **NATO ADatP** | `cargo run -p ainextgenc2 -- --adatp` | **100% — FULLY COMPLIANT** | 39/39 test vectors |
| **Workspace tests** | `cargo test --workspace` | Pass | All crate unit/integration tests |

---

## MIM manifest (`models/mim-full-5.1.json`)

| Metric | Count |
|--------|------:|
| Object types | 2,300 |
| Action types | 500 |
| Code lists | 401 |
| Attribute elements | 936 |
| Total manifest elements | 3,740 |
| Model version | 5.1.0 |

Regenerate:

```bash
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

Expected import output:

```
objects=2300 actions=500 code_lists=401 attributes=936 elements=3740
owl_properties=932 xml_tag_lines=1748 with_domain=932 imported=932 skipped=0
coverage=100.0% target=100% (MET)
```

### OWL import (`mim-import`)

| Metric | Value |
|--------|------:|
| Declared OWL properties (JC3IEDM) | 932 |
| Properties with resolved domain | 932 |
| Properties imported as MIM attributes | 932 |
| Skipped | 0 |
| Attribute coverage (declared properties) | **100%** |
| XML property tag lines (diagnostic only) | 1,748 |

Import pipeline:

1. Parse all `ObjectProperty` / `DatatypeProperty` declarations (including self-closing inverse stubs)
2. `resolve_property_domains()` — iterative `inverseOf` + `subPropertyOf` until stable
3. `ensure_property_domains_in_taxonomy()` — domain classes added to taxonomy
4. `import_owl_attributes()` — ancestor-walk domain resolution; 100% import target

**Not imported:** OWL reasoning, SHACL, or authoritative MIM 5.1 OWL (mimworld unavailable; bundled JC3IEDM v3.0 used).

---

## Deployment readiness

| Tier | Status | Notes |
|------|--------|-------|
| **Development / lab** | **Ready** | Full stack; conformance PKI; all compliance suites pass |
| **Coalition exercise** | **Partial** | Requires production PKI (`NmbTrustStore`), TLS/mTLS, SPIF-administered guard, durable audit |
| **Classified accredited** | **Not ready** | FIPS-validated module build, HSM, WORM audit, formal guard accreditation |

---

## Subsystem status

| Subsystem | Lab / conformance | Operational pilot | Gap |
|-----------|-------------------|-------------------|-----|
| STANAG 4774/4778 | Ready | Partial | Full national extensions; LDAP/SAML clearance |
| ZTDF (ACP-240 Supp. 3–4) | Ready (encoding) | Partial | No KAS protocol; no ABAC at decrypt |
| DCS cross-domain guard | Ready (config) | Partial | Conformance keys in demos; no accredited guard |
| MIP4-IES transport | Ready (100% dimensional) | Partial | No live HTTPS E2E in CI; JSON-LD wire profile |
| Policy plane (PIP/PDP/PEP) | Ready (subset) | Partial | No full CMBAC; `mission_id` not evaluated; static PIP |
| Crypto / PKI | Conformance + FIPS build path | Partial | Default `ring`; RSA outside FIPS module |
| Audit | In-memory + file JSONL | Partial | No WORM / SIEM connector |
| Scenarios | 5 demos | Demo only | Synthetic data; no live C2 integration |

---

## Bundled scenarios

| Scenario | Example | Demonstrates |
|----------|---------|--------------|
| `air_defense_radar` | `cargo run --example air_defense_radar` | Sensor → MIM tracks/targets |
| `dcs_cross_domain` | `cargo run --example dcs_cross_domain` | STANAG label + NMBS + ZTDF + guard downgrade |
| `mip4_ies_exchange` | `cargo run --example mip4_ies_exchange` | PEP-gated PutObject / GetByFilter |
| `allied_sensor_retrieval` | library API | USA→GBR coalition sync; national-only tracks hidden |
| `transport_exchange` | library API | Secured broker publish + filter |

**Not yet implemented:** SAR mission compartment, national/coalition dual-broker separation, LOC tactical release scenarios.

---

## Policy plane — precise capability

| Capability | Status |
|------------|--------|
| Classification vs clearance | Implemented |
| Nationality vs releasability (`REL TO`) | Implemented |
| Domain max classification ceiling | Implemented |
| Cross-domain downgrade + releasability intersection | Implemented |
| SPIF label validation at bind/guard | Implemented |
| Audit of permit/deny/downgrade | Implemented |
| Structured NATO clearance (XML/LDAP/SAML) | **Not implemented** |
| Full CMBAC permissive/restrictive category matrix | **Not implemented** |
| `mission_id` in PDP evaluation | **Not implemented** (field exists in context) |
| Handling-caveat enforcement in PDP | **Not implemented** (label model supports it) |
| LDAP/SAML PIP integration | **Not implemented** |

---

## Remaining priorities (operational path)

1. Mission-aware PDP + national/coalition compartment scenario
2. Production PKI defaults on HTTP server and DCS (feature-flag conformance keys)
3. Live HTTPS E2E in CI
4. MIP4-IES JSON-LD wire profile + NATO accreditation vectors
5. WORM / SIEM audit connectors
6. Signed SPIF distribution (NMRR-equivalent workflow)
7. KAS client + ABAC at ZTDF decrypt (ACP-240 full)

See [REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md) for detail. MIP4-IES transport detail: [MIP4-IES-FMN-READINESS.md](./MIP4-IES-FMN-READINESS.md).

---

## Verification

```bash
cargo test --workspace
cargo run -p ainextgenc2
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --mip4
cargo run -p ainextgenc2 -- --adatp
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

Exit code **0** on all `ainextgenc2` reports indicates full compliance for that suite.
