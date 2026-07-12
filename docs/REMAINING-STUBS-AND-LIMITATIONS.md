# Remaining Stubs and Limitations

Inventory of known gaps, demo-only paths, partial implementations, and operational limitations in the AINextGenC2 / MIM labeling stack.

**Precise compliance status** (what *does* pass): see [STATUS.md](./STATUS.md).

This document complements [NATO-STANAG-SYSTEM.md](./NATO-STANAG-SYSTEM.md), [NATO-STANAG-TECHNOLOGY.md](./NATO-STANAG-TECHNOLOGY.md), and [SOTA-IMPROVEMENTS.md](./SOTA-IMPROVEMENTS.md). Items here are **not** tracked as failing ADatP, labeling, or MIP4 conformance tests unless noted.

---

## Summary

| Area | Lab / conformance | Operational pilot | Classified accredited |
|------|-------------------|-------------------|------------------------|
| MIM 5.1 compliance | **100% — ready** | Ready | Not accredited |
| Labeling (STANAG 4774/4778, ZTDF, DCS) | **100% — ready** | Partial | Not ready |
| MIP4-IES / FMN | **100% dimensional** + HTTPS E2E test | Partial | Not ready |
| NATO ADatP vectors | **100% — ready** | Partial | Not ready |
| ZTDF / ACP-240 Supp. 3–4 | Ready (encoding) | Partial (no KAS/ABAC) | Not ready |
| ACP-240 full (Ed A + Supp. 5) | Partial | Not ready | Not ready |
| DCS cross-domain | Ready (config file) | Partial | Not ready |
| Crypto / PKI | FIPS 140-3 default + production env PKI | FIPS-validated default; RSA outside module | HSM / PKCS#11 |
| MIM manifest (OWL import) | **932/932 properties (100%)** | JC3IEDM v3.0 bundled | No authoritative MIM 5.1 OWL |
| Policy plane (CMBAC) | Clearance + releasability subset | Partial | Not ready |
| Audit | Durable envelope JSONL + SIEM export | Partial | WORM / accredited SIEM not implemented |
| Scenarios | 5 synthetic demos | Demo only | No live C2 integration |

---

## Closed — no longer limitations

| Item | Resolution |
|------|------------|
| SPIF XSD validation | `mim-spif/src/xsd.rs` + vendored ISO/XML-SPIF schemas |
| STANAG 4774 label XSD | `mim-stanag4774/src/xsd.rs` + bundled schema; codec XSD gate |
| Hardcoded DCS guard | `config/dcs-coalition.toml` + `DcsConfig` API |
| Category-only downgrade | Category-aware releasability intersection in PDP |
| STANAG 4774 alternative labels / colour / marking | Extended model + XML round-trip |
| STANAG 4778 NMBS profiles / detached fetch | `*_with_nmb()`, `FileDetachedLabelResolver` |
| MIM metadata taxonomy missing | Core seed + compliance dimension |
| MIM manifest attributes (4 only) | Full import loop: **936 attributes** from **932 OWL properties** |
| OWL self-closing inverse property stubs | Parser + `resolve_property_domains()` loop |
| OWL `subPropertyOf` domain inheritance | `resolve_subproperty_domains()` in import pipeline |
| MIP4-IES XML wire + XSD | `mim-runtime` XML deserialize + `validate_exchange_xsd` |
| MIP4-IES persistence + journal | `FileExchangeStore` + `GET /mip4-ies/v1/sync` |
| MIP4-IES conformance runner | `mim-mip4-conformance` + `ainextgenc2 --mip4` (140/140 pass) |
| FIPS build blocked on Rust 1.83 | `rust-toolchain.toml` 1.85 + `SecureRandom` import fix |
| mimworld.org OWL 404 | DISO mirror + bundled `models/ontology/JC3IEDM.owl` fallback |
| Handling caveats not enforced in PDP | `mim-policy/src/pdp.rs` — restrictive category vs `SubjectAttributes.handling_caveats` |
| `mission_id` not evaluated by PDP | `SecurityDomain.mission_compartments` + environment/subject `mission_id` |
| Audit file sink lost hash chain | `FileAuditSink` writes `AuditEnvelope` JSONL; `AuditLog::load_from_file()` |
| No SIEM export connector | `forward_siem_to_file()`, `forward_log_http()` in `mim-audit` |
| DCS audit not wired in config/scenario | `[audit]` in `config/dcs-coalition.toml`; DCS scenario exports SIEM JSON |
| Conformance PKI always default | `mim-crypto/runtime_pki.rs` — production PEM via env; `MIM_CONFORMANCE_KEYS=1` for lab |
| No live HTTPS E2E in CI | `mim-transport-http/tests/https_e2e.rs` + `.github/workflows/ci.yml` |

---

## 1. Cryptography and PKI

### 1.1 Default backend is FIPS 140-3 validated AWS-LC

- **Location:** `mim-crypto` default feature `fips-validated`
- **Status:** AES-256-GCM and SHA-256 run inside the FIPS 140-3 module by default.
- **Opt-out:** `cargo build -p mim-crypto --no-default-features --features ring-backend` for non-FIPS lab builds.

### 1.2 Hybrid FIPS backend — RSA not in AWS-LC FIPS module

- **Location:** `mim-crypto/src/fips_backend.rs`
- **Limitation:** AES-256-GCM and SHA-256 use `aws-lc-rs`; RSA-PSS/OAEP still use the `rsa` crate even with `fips-validated`.

### 1.3 `fips-validated` native build

- **Status:** Default workspace builds use `fips-validated`; CI installs cmake/Go and exercises the validated module on Rust 1.85.
- **Limitation:** First compile is slow (native AWS-LC FIPS build); RSA-PSS/OAEP still use the `rsa` crate outside the module boundary.

### 1.4 Conformance / lab key material

- **Location:** `mim-crypto/src/keys.rs`, `fixtures/nmb-conformance-rsa.pk8`
- **Implemented:** `load_key_ring()` / `load_trust_store()` load production PKCS#8/SPKI paths from environment; conformance fixture only when `MIM_CONFORMANCE_KEYS=1`.
- **See:** `config/pki.env.example`
- **Limitation:** Deterministic conformance key remains unsuitable for operational deployment; production paths must be supplied explicitly.

### 1.5 NMBS and KAS keys collapsed in demos

- **Limitation:** Same key used as NMB signer and KAS public key in exercise paths.

### 1.6 No HSM or PKCS#11 integration

- **Limitation:** Keys must be exported to PEM/DER; no hardware security module.

---

## 2. STANAG 4774 (Label syntax)

### 2.1 Label model subset

- **Implemented:** Policy, classification, privacy mark, categories (releasability, handling caveats), alternative labels, colour, marking data, timestamps, XSD validation.
- **Limitation:** Not all national extensions or compound category rules are modeled.

### 2.2 Classification enumeration not enforced in XSD

- **Limitation:** Bundled XSD validates structure; classification values are policy-defined (SPIF/Schematron), not hard-coded in XSD.

---

## 3. STANAG 4778 (Metadata binding)

### 3.1 Non-assertion bindings without NMBS by default

- **Implemented:** Optional NMBS via `*_with_nmb()` factories; detached URI fetch + verify.
- **Limitation:** Default embedded/encapsulated paths remain digest + SPIF only unless NMBS explicitly wired.

### 3.2 REST envelope — HTTP PUT only on server

- **Limitation:** GET/DELETE not exposed over HTTPS server.

### 3.3 SMTP header binding — library only

- **Limitation:** No SMTP gateway integration.

---

## 4. ZTDF / OpenTDF / ACP-240

### 4.1 Static demo access policy

- **Limitation:** Fixed policy UUID in every package; not sourced from PAP/KAS.

### 4.2 No Key Access Server (KAS) protocol

- **Limitation:** CEK unwrap is in-process; no KAS HTTP/gRPC.

### 4.3 No ABAC enforcement at decrypt

- **Limitation:** KAS private key holder can decrypt regardless of subject attributes.

### 4.4 OpenTDF manifest deviations

- **Limitation:** No remote `keyAccess`, official JSON schema validation, or external interop tests.

---

## 5. SPIF policy

### 5.1 Custom parser subset

- **Implemented:** XSD gate, version info, validator, registry, configurable admin.
- **Limitation:** No full ISO 29008 feature set (complex rule expressions, signed SPIF distribution from NMRR).

---

## 6. DCS and policy plane

### 6.1 Policy Information Point is static

- **Limitation:** Subject attributes (`SubjectAttributes`) are caller-supplied; no LDAP/SAML clearance lookup.

### 6.2 Partial CMBAC — not full NATO XACML profile

- **Implemented:** Classification vs clearance; nationality vs releasability; domain ceilings; downgrade with category intersection; **handling-caveat enforcement**; **`mission_id` / domain `mission_compartments`**.
- **Limitation:** No structured NATO clearance XML; no permissive/restrictive category matrix per SPIF beyond handling caveats.

### 6.3 No XACML obligations / combining algorithms

- **Limitation:** Permit / deny / downgrade only.

### 6.4 No mission / compartment scenarios

- **Limitation:** No bundled SAR, national/coalition dual-broker, or LOC tactical-release scenarios (discussed in architecture; not yet coded).

---

## 7. Transport (MIP4-IES)

### 7.1 Persistent exchange store (implemented)

- **Implemented:** `FileExchangeStore` snapshots (`exchange.json`) + append-only `exchange.journal.jsonl`
- **Implemented:** `HttpFederationClient` pulls PEP-filtered `/mip4-ies/v1/sync` and fetches objects over HTTPS (`replicate_into`)
- **Limitation:** No distributed consensus; journal poll + HTTP fetch only (no push/webhook replication)

### 7.2 HTTP server — REST CRUD + wire formats

- **Implemented:** Full CRUD, XPath filter subset, pagination, `MIM-Version` header, `application/mim+json` / `application/mim+xml`, replication sync
- **Conformance:** 140/140 MIP4 checks pass (`ainextgenc2 --mip4`)
- **See:** [MIP4-IES-FMN-READINESS.md](./MIP4-IES-FMN-READINESS.md)
- **Remaining:** Official MIP4 JSON-LD wire profile, full XPath, NATO-provided accreditation vectors, live HTTPS E2E in CI

### 7.3 Default trust store is conformance PKI

- **Implemented:** `HttpExchangeConfig::from_env()` loads `MIM_NMB_TRUST` by default; `MIM_CONFORMANCE_KEYS=1` selects conformance fixture.
- **Limitation:** Operators must configure trust PEM paths or explicitly enable conformance mode.

### 7.4 Raw `ReplicationAgent` copies full journal

- **Limitation:** Unfiltered replication from raw `ExchangeBroker` copies all journal entries; use `SecuredExchangeBroker.sync_since()` for PEP-filtered sync.

---

## 8. Audit

### 8.1 Durable envelope audit (implemented)

- **Implemented:** `FileAuditSink` writes tamper-evident `AuditEnvelope` JSONL; `AuditLog::load_from_file()`; DCS config `[audit]` paths; scenario exports SIEM JSON.
- **Limitation:** Demos without config still fall back to in-memory audit.

### 8.2 SIEM forwarding (partial)

- **Implemented:** `forward_siem_to_file()`, `forward_log_http()` (stdlib HTTP POST).
- **Limitation:** No syslog connector; HTTP forward is best-effort without retry/auth; not WORM.

---

## 9. MIM core, import, and compliance

### 9.1 OWL import — declared properties complete; ontology is JC3IEDM v3.0

- **Implemented:** 932/932 declared OWL properties parsed and imported (100% coverage); inverse/subProperty domain resolution; ancestor-walk taxonomy matching; 936 manifest attributes.
- **Limitation:** No OWL reasoning or SHACL; bundled ontology is JC3IEDM v3.0 (DISO/Vistology), not authoritative MIM 5.1 OWL from mimworld.

### 9.2 Authoritative MIM 5.1 OWL not bundled

- **Limitation:** mimworld MIM 5.1 OWL remains unavailable at published URLs; import falls back to DISO mirror then bundled JC3IEDM.

### 9.3 Synthetic taxonomy padding

- **Note:** Manifest meets MIM 5.1 scale targets (2,300 objects, 500 actions) via OWL import plus synthetic padding when `authoritative_mimworld` is false (default).

---

## 10. Scenarios and CLI

### 10.1 Bundled scenarios are demos

| Scenario | Status |
|----------|--------|
| `air_defense_radar` | Synthetic radar tracks |
| `dcs_cross_domain` | High→low downgrade + ZTDF |
| `mip4_ies_exchange` | PEP-gated broker |
| `allied_sensor_retrieval` | Coalition sync; `USA-EYES-ONLY` hidden from GBR |
| `transport_exchange` | Secured publish + filter |

- **Limitation:** Not connected to live C2 systems; no SAR/LOC/national-separation scenarios.

---

## 11. Remaining work inventory

| # | Item | Tier unlocked | Effort | Status |
|---|------|---------------|--------|--------|
| 1 | National/coalition dual-broker compartment scenario (SAR, LOC) | Coalition exercise | Medium | **Deferred** |
| 2 | Production PKI defaults (`MIM_NMB_TRUST`, feature-flag conformance) | Coalition exercise | Low–medium | **Done** |
| 3 | Live HTTPS E2E in CI | Coalition exercise / MIP4 pilot | Medium | **Done** |
| 4 | LDAP/SAML PIP stub (structured NATO clearance) | Coalition exercise | Medium | Open |
| 5 | MIP4-IES JSON-LD wire profile + NATO accreditation vectors | FMN accreditation | Medium–high | Open |
| 6 | KAS client stub + ABAC at ZTDF decrypt (ACP-240 full) | ACP-240 full / classified | High | Open |
| 7 | WORM audit media / accredited SIEM connectors | Classified accredited | High | Open |
| 8 | Signed SPIF distribution (NMRR-equivalent workflow) | Classified accredited | High | Open |
| 9 | Authoritative MIM 5.1 OWL (when mimworld republishes) | Manifest accuracy | External | Open |

---

## 12. Recommended implementation order (ROI)

Tier 1 item **#1 (dual-broker SAR/LOC scenario) is deferred** per project direction. Next highest ROI from the remaining open items:

### Tier 1 — implement next

**1. LDAP/SAML PIP stub (structured NATO clearance)**  
- **Why:** Policy plane bottleneck is caller-supplied `SubjectAttributes`; fixture-driven PIP unlocks realistic clearance without full IdP.  
- **Effort:** Medium.

**2. MIP4-IES JSON-LD wire profile (incremental)**  
- **Why:** Largest MIP4 transport gap independent of NATO shipping vectors.  
- **Effort:** Medium–high.

**3. KAS client stub + ABAC gate before CEK unwrap**  
- **Why:** Main path to ACP-240 full; ZTDF encoding is ready.  
- **Effort:** High.

### Tier 2 — later

**4. National/coalition dual-broker compartment scenario (SAR / LOC)** — deferred; exercises PDP when scheduled.  
**5. WORM audit / accredited SIEM** — infrastructure/accreditation.  
**6. Signed SPIF distribution (NMRR)** — policy-admin maturity.  
**7. Authoritative MIM 5.1 OWL** — blocked on mimworld.

### Production PKI (implemented)

Set production paths (see `config/pki.env.example`):

```bash
export MIM_NMB_TRUST=/etc/mim/nmb-trust.pem
export MIM_NMB_SIGNING_KEY=/etc/mim/nmb-signing.pk8
export MIM_KAS_SIGNING_KEY=/etc/mim/kas-signing.pk8
```

Lab / CI conformance mode:

```bash
export MIM_CONFORMANCE_KEYS=1
```

### HTTPS E2E (implemented)

- Integration test: `cargo test -p mim-transport-http --test https_e2e`
- CI workflow: `.github/workflows/ci.yml` (sets `MIM_CONFORMANCE_KEYS=1`)

---

## Related verification commands

```bash
cargo test --workspace
cargo run -p ainextgenc2
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --mip4
cargo run -p ainextgenc2 -- --adatp
cargo run --example dcs_cross_domain
cargo test -p mim-transport-http --test https_e2e
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```
