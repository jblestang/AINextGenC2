# AINextGenC2 — Precise Status

Last verified: **2026-07-12** (branch `cursor/real-federation-http-d2ec`, HTTPS federation + LDAP PIP stub).

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
| **Coalition exercise** | **Partial** | Requires production PKI (`NmbTrustStore`), TLS/mTLS, SPIF-administered guard, WORM/accredited SIEM |
| **Classified accredited** | **Not ready** | FIPS-validated module build, HSM, WORM audit, formal guard accreditation |

---

## Subsystem status

| Subsystem | Lab / conformance | Operational pilot | Gap |
|-----------|-------------------|-------------------|-----|
| STANAG 4774/4778 | Ready | Partial | Full national extensions; LDAP/SAML clearance |
| ZTDF (ACP-240 Supp. 3–4) | Ready (encoding) | Partial | No KAS protocol; no ABAC at decrypt |
| DCS cross-domain guard | Ready (config) | Partial | Conformance keys in demos; no accredited guard |
| MIP4-IES transport | Ready (100% dimensional + HTTPS E2E) | Partial | JSON-LD wire profile; push/webhook replication |
| Policy plane (PIP/PDP/PEP) | Ready (subset + LDAP PIP stub) | Partial | No full CMBAC; live LDAP/SAML IdP; static PIP fallback |
| Crypto / PKI | FIPS 140-3 default + production env PKI | Partial | RSA outside FIPS module; HSM not integrated |
| Audit | Durable envelope JSONL + SIEM export | Partial | No WORM media; HTTP SIEM is best-effort |
| Scenarios | 5 demos | Demo only | Synthetic data; no live C2 integration |

---

## Bundled scenarios

| Scenario | Example | Demonstrates |
|----------|---------|--------------|
| `air_defense_radar` | `cargo run --example air_defense_radar` | Sensor → MIM tracks/targets |
| `dcs_cross_domain` | `cargo run --example dcs_cross_domain` | STANAG label + NMBS + ZTDF + guard downgrade |
| `mip4_ies_exchange` | `cargo run --example mip4_ies_exchange` | PEP-gated PutObject / GetByFilter |
| `allied_sensor_retrieval` | `cargo run --example allied_c2_sensor_retrieval` | USA→GBR coalition sync; set `MIM_FEDERATION_HTTP=1` for HTTPS federation |
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
| Audit of permit/deny/downgrade | Implemented (PEP + DCS transfer) |
| Handling-caveat enforcement in PDP | **Implemented** (restrictive categories vs subject caveats) |
| `mission_id` in PDP evaluation | **Implemented** (domain `mission_compartments`) |
| Durable audit envelopes (`FileAuditSink`) | **Implemented** |
| SIEM JSON export / HTTP forward | **Implemented** (`forward_siem_to_file`, `forward_log_http`) |
| LDAP PIP stub (fixture-driven clearance lookup) | **Implemented** (`mim-policy/ldap_pip`, `config/fmn-ldap-pip.toml`) |
| Structured NATO clearance (XML/LDAP/SAML) | **Partial** (fixture LDAP; no live IdP) |
| Full CMBAC permissive/restrictive category matrix | **Not implemented** |
| SAML PIP integration | **Not implemented** |

---

## Remaining priorities (operational path)

1. National/coalition dual-broker compartment scenario (SAR, LOC)
2. MIP4-IES JSON-LD wire profile + NATO accreditation vectors
3. Live LDAP/SAML IdP integration (beyond fixture PIP)
4. WORM audit media / accredited SIEM connectors
5. Signed SPIF distribution (NMRR-equivalent workflow)
6. KAS client + ABAC at ZTDF decrypt (ACP-240 full)

See [REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md) for detail. MIP4-IES transport detail: [MIP4-IES-FMN-READINESS.md](./MIP4-IES-FMN-READINESS.md).

---

## Verification

```bash
cargo test --workspace
cargo test -p mim-transport-http --test https_e2e
cargo test -p mim-transport-http --test federation_e2e
MIM_FEDERATION_HTTP=1 cargo run --example allied_c2_sensor_retrieval
cargo run -p ainextgenc2
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --mip4
cargo run -p ainextgenc2 -- --adatp
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

Exit code **0** on all `ainextgenc2` reports indicates full compliance for that suite.
