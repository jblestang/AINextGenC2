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
| MIP4-IES / FMN | **100% dimensional** | Partial | Not ready |
| NATO ADatP vectors | **100% — ready** | Partial | Not ready |
| ZTDF / ACP-240 Supp. 3–4 | Ready (encoding) | Partial (no KAS/ABAC) | Not ready |
| ACP-240 full (Ed A + Supp. 5) | Partial | Not ready | Not ready |
| DCS cross-domain | Ready (config file) | Partial | Not ready |
| Crypto / PKI | Conformance keys; FIPS build verified | PKI loaders exist; not default | RSA outside FIPS module |
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

---

## 1. Cryptography and PKI

### 1.1 Default backend is non-FIPS `ring`

- **Location:** `mim-crypto` default feature `ring-backend`
- **Limitation:** Production builds use `ring` unless `--features fips` or `fips-validated` is selected.

### 1.2 Hybrid FIPS backend — RSA not in AWS-LC FIPS module

- **Location:** `mim-crypto/src/fips_backend.rs`
- **Limitation:** AES-256-GCM and SHA-256 use `aws-lc-rs`; RSA-PSS/OAEP still use the `rsa` crate even with `fips-validated`.

### 1.3 `fips-validated` native build

- **Status:** `fips` feature builds and tests pass on Rust 1.85.
- **Limitation:** `fips-validated` (FIPS 140-3 module) requires native AWS-LC FIPS build (cmake, long compile); not exercised in default CI.

### 1.4 Conformance / lab key material

- **Location:** `mim-crypto/src/keys.rs`, `fixtures/nmb-conformance-rsa.pk8`
- **Limitation:** Deterministic 2048-bit RSA fixture; not suitable for operational deployment.

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
- **Limitation:** No distributed consensus or multi-node replication protocol beyond journal poll

### 7.2 HTTP server — REST CRUD + wire formats

- **Implemented:** Full CRUD, XPath filter subset, pagination, `MIM-Version` header, `application/mim+json` / `application/mim+xml`, replication sync
- **Conformance:** 140/140 MIP4 checks pass (`ainextgenc2 --mip4`)
- **See:** [MIP4-IES-FMN-READINESS.md](./MIP4-IES-FMN-READINESS.md)
- **Remaining:** Official MIP4 JSON-LD wire profile, full XPath, NATO-provided accreditation vectors, live HTTPS E2E in CI

### 7.3 Default trust store is conformance PKI

- **Limitation:** HTTP server trusts conformance NMBS key unless configured with `NmbTrustStore`.

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

## 11. Suggested remediation priority

1. **National/coalition compartment scenario** (SAR, LOC, dual-broker)
2. **Production PKI** wired into DCS scenario and HTTP server defaults (feature-flag conformance)
3. **Live HTTPS E2E** in CI
4. **MIP4-IES JSON-LD wire profile** and NATO accreditation test vectors
5. **LDAP/SAML clearance** in PIP (structured NATO clearance)
6. **WORM / SIEM connectors** for audit pipeline
7. **Signed SPIF distribution** workflow (NMRR-equivalent)
8. **KAS client stub** with ABAC gate before CEK unwrap
9. **Authoritative MIM 5.1 OWL** when MIP republishes mimworld downloads

---

## Related verification commands

```bash
cargo test --workspace
cargo run -p ainextgenc2
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --mip4
cargo run -p ainextgenc2 -- --adatp
cargo run -p mim-import -- --source bundled:jc3iedm \
  --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
```
