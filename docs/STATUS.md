# AINextGenC2 — Precise Status

Last verified: **2026-07-11** (workspace on `main`, commit `d4a5aa1` — PR #13 STANAG/audit merge).

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
| DCS cross-domain guard | Ready (config + audit) | Partial | Conformance keys in demos; no accredited guard |
| MIP4-IES transport | Ready (100% dimensional) | Partial | No live HTTPS E2E in CI; JSON-LD wire profile |
| Policy plane (PIP/PDP/PEP) | Ready (caveats + mission) | Partial | No full CMBAC; LDAP/SAML PIP; static PIP |
| Crypto / PKI | Conformance + FIPS build path | Partial | Default `ring`; RSA outside FIPS module |
| Audit | Durable envelope JSONL + SIEM export | Partial | No WORM media; HTTP SIEM is best-effort |
| Scenarios | 5 demos | Demo only | Synthetic data; no live C2 integration |

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
| `allied_sensor_retrieval` | library API | USA→GBR coalition sync; national-only tracks hidden |
| `transport_exchange` | library API | Secured broker publish + filter |

**Not yet implemented:** SAR mission compartment, national/coalition dual-broker separation, LOC tactical release scenarios.

---

## Limitations

Conformance suites report **100%**; the items below are **operational and architectural gaps** that do not fail automated compliance today.

### By deployment tier

| Tier | Blockers |
|------|----------|
| **Lab / development** | None — full stack runs with conformance PKI |
| **Coalition exercise** | Production PKI not default; HTTP server uses conformance trust store; no live HTTPS E2E in CI; no SAR/LOC/dual-broker scenarios; SIEM forward is best-effort |
| **Classified accredited** | FIPS-validated module not default CI path; RSA outside FIPS boundary; no HSM/PKCS#11; no WORM audit; no accredited guard; no full CMBAC; no LDAP/SAML PIP |

### By subsystem

| Subsystem | Limitation | Impact |
|-----------|------------|--------|
| **STANAG 4774** | National extensions and compound category rules not fully modeled; classification values not XSD-enforced | Cannot represent all national label profiles |
| **STANAG 4778** | Non-assertion bindings lack NMBS by default; SMTP binding library-only; HTTPS server exposes PUT only | Cross-domain still requires assertion binding (by design) |
| **ZTDF / ACP-240** | Static demo access policy; no KAS protocol; no ABAC at decrypt; OpenTDF manifest subset | CEK unwrap is in-process; holder can decrypt without attribute check |
| **SPIF** | Parser subset; no signed SPIF distribution (NMRR workflow) | Policy admin is file-based, not centrally signed |
| **Policy plane** | PIP is caller-supplied (no LDAP/SAML); no full CMBAC matrix; no XACML obligations | Clearance comes from application, not enterprise IdP |
| **DCS** | Conformance keys in demos; no accredited guard; no dual-broker national/coalition separation | Exercise-ready, not deployment-accredited |
| **MIP4-IES** | No JSON-LD wire profile in CI; XPath subset only; no NATO-provided accreditation vectors; journal poll only (no P2P protocol) | 100% dimensional conformance; operational interop gaps remain |
| **Crypto / PKI** | Default `ring`; NMBS/KAS keys collapsed in demos; no HSM | Keys exported as PEM/DER |
| **Audit** | In-memory fallback when `[audit]` unset; HTTP SIEM has no auth/retry/syslog; not WORM | Durable JSONL works; accredited logging pipeline incomplete |
| **MIM import** | JC3IEDM v3.0 bundled (not authoritative MIM 5.1 OWL); no OWL reasoning/SHACL | Scale targets met; ontology source is fallback |
| **Scenarios** | 5 synthetic demos; no live C2; no SAR/LOC/national-separation | Architecture patterns discussed but not demonstrated |

### Recently closed (PR #13)

| Was a limitation | Now |
|------------------|-----|
| Handling caveats not enforced in PDP | `SubjectAttributes.handling_caveats` checked against restrictive label categories |
| `mission_id` ignored by PDP | `SecurityDomain.mission_compartments` + environment `mission_id` evaluated |
| `FileAuditSink` wrote raw records (chain lost on disk) | Tamper-evident `AuditEnvelope` JSONL + `load_from_file()` |
| DCS demos used ephemeral in-memory audit only | `[audit]` in `config/dcs-coalition.toml`; scenario exports SIEM JSON |
| DCS compliance dimension did not verify audit count | Requires `audit.len() >= 2` and chain verify |

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
| Structured NATO clearance (XML/LDAP/SAML) | **Not implemented** |
| Full CMBAC permissive/restrictive category matrix | **Not implemented** |
| LDAP/SAML PIP integration | **Not implemented** |

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

## Remaining priorities (operational path)

| # | Item | Tier unlocked | Effort |
|---|------|---------------|--------|
| 1 | National/coalition dual-broker compartment scenario (SAR, LOC) | Coalition exercise | Medium |
| 2 | Production PKI defaults on HTTP server and DCS (feature-flag conformance keys) | Coalition exercise | Low–medium |
| 3 | Live HTTPS E2E in CI | Coalition exercise / MIP4 pilot | Medium |
| 4 | MIP4-IES JSON-LD wire profile + NATO accreditation vectors | FMN accreditation | Medium–high |
| 5 | WORM audit media / accredited SIEM connectors | Classified accredited | High |
| 6 | Signed SPIF distribution (NMRR-equivalent workflow) | Classified accredited | High |
| 7 | KAS client + ABAC at ZTDF decrypt (ACP-240 full) | ACP-240 full / classified | High |

See [REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md) for detail. MIP4-IES transport detail: [MIP4-IES-FMN-READINESS.md](./MIP4-IES-FMN-READINESS.md).

---

## Recommended implementation order (ROI)

Ranked by **value unlocked per engineering effort**, given the current stack (100% conformance, handling-caveat + mission PDP, durable audit in place).

### Tier 1 — implement first (highest ROI)

**1. National/coalition dual-broker compartment scenario (SAR / LOC)**  
- **Why:** Exercises the PDP features just shipped (`mission_id`, handling caveats, releasability filtering) in a realistic joint-ops pattern; turns architecture discussion into runnable proof.  
- **Unlocks:** Coalition exercise credibility; PEP-filtered `SecuredExchangeBroker` vs raw journal; national-only vs coalition data separation.  
- **Scope:** New scenario + `config/dcs-sar.toml` (or similar) with `mission_compartments`, dual brokers, `LOCSEN`/SAR labels; compliance dimension optional.  
- **Effort:** Medium — mostly wiring existing crates; no new crypto or transport protocol.

**2. Production PKI defaults (feature-flag conformance keys)**  
- **Why:** Smallest change that moves the stack from “lab keys” to “exercise keys”; `NmbTrustStore` and PKCS#8 loaders already exist.  
- **Unlocks:** Coalition exercise tier; HTTP server and DCS guard stop trusting conformance fixture by default when `MIM_CONFORMANCE_KEYS=1` is unset.  
- **Scope:** Default `HttpExchangeConfig` / DCS to `NmbTrustStore::from_spki_pem_files`; conformance behind explicit feature or env flag.  
- **Effort:** Low–medium — config + scenario updates + docs.

**3. Live HTTPS E2E in CI**  
- **Why:** MIP4-IES is 100% dimensional in unit tests but has no runtime HTTPS regression gate; catches rustls/envelope/PEP integration breaks.  
- **Unlocks:** MIP4 operational pilot confidence; documents the coalition REST binding end-to-end.  
- **Scope:** `mim-transport-http` integration test: spin `HttpExchangeServer`, PUT envelope, GET by OID, assert PEP deny/permit.  
- **Effort:** Medium — CI plumbing + self-signed cert fixture.

### Tier 2 — implement next (strong value, more cost)

**4. LDAP/SAML PIP stub (structured NATO clearance)**  
- **Why:** Policy plane bottleneck is static `SubjectAttributes`; a file- or fixture-driven PIP adapter unlocks realistic clearance without full IdP integration.  
- **Unlocks:** Structured clearance XML path; reduces “caller-supplied clearance” risk in demos.  
- **Effort:** Medium.

**5. MIP4-IES JSON-LD wire profile (incremental)**  
- **Why:** Closes the largest documented MIP4 transport gap that does not depend on NATO shipping vectors.  
- **Unlocks:** FMN wire-format alignment; pairs with existing JSON-LD roundtrip tests.  
- **Effort:** Medium–high; NATO vectors (item 4 dependency) may arrive later.

**6. KAS client stub + ABAC gate before CEK unwrap**  
- **Why:** Largest functional gap for ACP-240 full edition; ZTDF encoding is ready.  
- **Unlocks:** Decrypt-time attribute check; path to Supp. 5 interop.  
- **Effort:** High — new protocol surface.

### Tier 3 — defer until accredited deployment (lower ROI now)

**7. WORM audit / accredited SIEM** — infrastructure and accreditation process; durable JSONL + SIEM export already cover lab and coalition rehearsal.  
**8. Signed SPIF distribution (NMRR)** — policy-admin maturity; current SPIF XSD + registry sufficient for conformance.  
**9. Authoritative MIM 5.1 OWL** — blocked on mimworld republication; JC3IEDM fallback meets scale targets.

### Suggested sprint sequence

```
Sprint A: dual-broker SAR scenario + production PKI defaults
Sprint B: HTTPS E2E CI + LDAP/SAML PIP fixture adapter
Sprint C: JSON-LD wire profile + KAS client stub (parallel if staffed)
```

---

## Verification

```bash
cargo test --workspace
cargo run -p ainextgenc2
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --mip4
cargo run -p ainextgenc2 -- --adatp
cargo run --example dcs_cross_domain
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```

Exit code **0** on all `ainextgenc2` reports indicates full compliance for that suite.
