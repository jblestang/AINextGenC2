# AINextGenC2 — Precise Status

Last verified: **2026-07-12** (coalition exercise tier: JSON-LD, LDAP/SAML PIP, KAS ABAC, webhook notify+pull).

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
| **Coalition exercise** | **Ready** | Config-driven federation (`FederationConfig`); production PKI via `MIM_NMB_TRUST` + `pki_env`; HTTPS/mTLS + LDAP/SAML PIP → PEP; webhook notify + pull replication; `coalition_exercise` runner |
| **Classified accredited** | **Not ready** | FIPS-validated module build, HSM, WORM audit, formal guard accreditation |

---

## Subsystem status

| Subsystem | Lab / conformance | Operational pilot | Gap |
|-----------|-------------------|-------------------|-----|
| STANAG 4774/4778 | Ready | Partial | Full national extensions in production IdP |
| ZTDF (ACP-240 Supp. 3–4) | Ready (encoding + ABAC decrypt gate) | Partial | Remote KAS protocol; full OpenTDF schema |
| DCS cross-domain guard | Ready (config + audit) | Partial | Conformance keys in demos; no accredited guard |
| MIP4-IES transport | Ready (100% dimensional + HTTPS/JSON-LD E2E) | Ready | NATO accreditation vectors; full XPath |
| Policy plane (PIP/PDP/PEP) | Ready (caveats + mission + LDAP/SAML PIP) | Ready | No full CMBAC; production IdP wiring |
| Crypto / PKI | FIPS 140-3 default + separate NMB/KAS keys | Ready | RSA outside FIPS module; HSM not integrated |
| Audit | Durable envelope JSONL + SIEM export | Partial | No WORM media; HTTP SIEM is best-effort |
| Scenarios | 6 demos + coalition exercise | Ready | Synthetic data; no live C2 integration |

---

## Audit trail (`mim-audit`)

| Component | Status | Detail |
|-----------|--------|--------|
| Hash-chained envelopes | **Implemented** | `AuditEnvelope` with `previousHash` / `recordHash` |
| NMBS-signed audit records | **Implemented** | `AuditLog::with_signing_key()` |
| In-memory sink | **Implemented** | `AuditLog::memory()` — tests and fallback |
| Durable file sink | **Implemented** | `FileAuditSink` writes envelope JSONL (not raw records) |
| Chain reload | **Implemented** | `AuditLog::load_from_file()` + `verify_chain()` |
| SIEM JSON export | **Implemented** | `export_siem()` / `forward_siem_to_file()` |
| HTTP SIEM forward | **Implemented** | `forward_log_http()` — stdlib HTTP POST (best-effort) |
| DCS config wiring | **Implemented** | `[audit]` in `config/dcs-coalition.toml` |
| WORM / accredited SIEM | **Not implemented** | No write-once media; no syslog/auth/retry |

Default coalition audit paths (relative to `config/dcs-coalition.toml`):

```toml
[audit]
path = "../target/dcs-audit.jsonl"
siemExportPath = "../target/dcs-siem.json"
```

The DCS cross-domain scenario signs audit records, persists envelopes when configured, exports SIEM JSON, and verifies the hash chain on completion.

---

## Bundled scenarios

| Scenario | Example | Demonstrates |
|----------|---------|--------------|
| `air_defense_radar` | `cargo run --example air_defense_radar` | Sensor → MIM tracks/targets |
| `dcs_cross_domain` | `cargo run --example dcs_cross_domain` | STANAG label + NMBS + ZTDF + guard downgrade + durable audit |
| `mip4_ies_exchange` | `cargo run --example mip4_ies_exchange` | PEP-gated PutObject / GetByFilter |
| `allied_sensor_retrieval` | `cargo run --example allied_c2_sensor_retrieval` | USA→GBR coalition sync; set `MIM_FEDERATION_HTTP=1` for HTTPS federation |
| `coalition_exercise` | `cargo run --example coalition_exercise` | Config-driven FMN exercise (`config/fmn-federation.toml`); production PKI via `pki_env` |
| `transport_exchange` | library API | Secured broker publish + filter |

**Not yet implemented:** SAR mission compartment, national/coalition dual-broker separation, LOC tactical release scenarios.

---

## Limitations and roadmap

Full inventory of gaps, closed items, and ROI-ranked implementation order:

**[REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md)**

**Top ROI picks (Tier 1):**

1. National/coalition dual-broker SAR/LOC scenario
2. MIP4-IES JSON-LD wire profile + NATO accreditation vectors
3. Live LDAP/SAML IdP integration (beyond fixture PIP)

MIP4-IES transport detail: [MIP4-IES-FMN-READINESS.md](./MIP4-IES-FMN-READINESS.md).

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
| Handling-caveat enforcement in PDP | **Implemented** (restrictive categories vs `SubjectAttributes.handling_caveats`) |
| `mission_id` in PDP evaluation | **Implemented** (`SecurityDomain.mission_compartments`) |
| Durable audit envelopes (`FileAuditSink`) | **Implemented** |
| SIEM JSON export / HTTP forward | **Implemented** (`forward_siem_to_file`, `forward_log_http`) |
| LDAP PIP (fixture + live LDAP + SAML bearer) | **Implemented** |
| Structured NATO clearance (XML/LDAP/SAML) | **Partial** (live LDAP/SAML lab adapters) |
| Full CMBAC permissive/restrictive category matrix | **Not implemented** |
| SAML PIP integration (bearer claims) | **Implemented** (lab profile; JSON claims in `Authorization: Bearer`) |

### STANAG 4774 handling caveats (PDP)

Labels with restrictive categories (e.g. UK DEMO `LOCSEN`) are denied unless the subject holds matching caveats:

```rust
SubjectAttributes::new("operator", ClassificationLevel::Secret)
    .with_handling_caveat("LOCSEN")
```

### Mission compartments (PDP)

Domains may declare authorized mission compartments. Cross-domain transfers into/out of compartmented domains require a matching `mission_id`:

```rust
SecurityDomain::new("DOMAIN-SAR", "SAR High Side", ClassificationLevel::Secret)
    .with_mission_compartments(vec!["SAR-OPS-1".into()]);
```

---

## Verification

```bash
cargo test --workspace
cargo test -p mim-transport-http --test https_e2e
cargo test -p mim-transport-http --test federation_e2e
cargo test -p mim-transport-http --test webhook_e2e
cargo test -p mim-transport-http --test saml_identity_e2e
MIM_FEDERATION_HTTP=1 cargo run --example allied_c2_sensor_retrieval
MIM_CONFORMANCE_KEYS=1 cargo run --example coalition_exercise
cargo run -p ainextgenc2
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --mip4
cargo run -p ainextgenc2 -- --adatp
cargo run --example dcs_cross_domain
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

Exit code **0** on all `ainextgenc2` reports indicates full compliance for that suite.
