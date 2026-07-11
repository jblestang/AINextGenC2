# Remaining Stubs and Limitations

Inventory of known gaps, demo-only paths, partial implementations, and operational limitations in the AINextGenC2 / MIM labeling stack as of the `cursor/nato-stanag-p1-p3-0965` branch.

This document complements [NATO-STANAG-SYSTEM.md](./NATO-STANAG-SYSTEM.md) and [NATO-STANAG-TECHNOLOGY.md](./NATO-STANAG-TECHNOLOGY.md). Items here are **not** tracked as failing ADatP or labeling compliance tests unless noted.

---

## Summary

| Area | Lab / exercise | Operational pilot | Classified accredited |
|------|----------------|-------------------|------------------------|
| STANAG 4774/4778 core | Ready | Partial | Not ready |
| ZTDF / ACP-240 Supp. 3–4 | Ready (encoding) | Partial (no KAS/ABAC) | Not ready |
| ACP-240 full (Ed A + Supp. 5) | Partial | Not ready | Not ready |
| DCS cross-domain | Ready (preset guard) | Partial (SPIF admin exists; demos use presets) | Not ready |
| MIP4-IES transport | Partial | Partial | Not ready |
| Crypto / PKI | Conformance keys | PKI loaders exist; not default | FIPS build blocked |
| Audit | In-memory / file JSONL | Partial | WORM / HSM not implemented |

---

## 1. Cryptography and PKI

### 1.1 Default backend is non-FIPS `ring`

- **Location:** `mim-crypto` default feature `ring-backend`
- **Behavior:** Production builds use the `ring` crate unless `--features fips` or `fips-validated` is selected.
- **Limitation:** Labeling compliance dimension `FipsCrypto` scores 1.0 on `ring` with a message to rebuild for FIPS; that is a **readiness hint**, not validated FIPS 140-3 operation.

### 1.2 FIPS / FIPS-validated build blocked on toolchain

- **Location:** `mim-crypto/Cargo.toml`, `fips_backend.rs`
- **Behavior:** `cargo test -p mim-crypto --features fips` fails on Rust 1.83 because `aws-lc-sys` pulls `jobserver@0.1.35` (requires Rust ≥ 1.85).
- **Limitation:** FIPS-capable and FIPS-validated modules cannot be verified in CI on the current toolchain.

### 1.3 Hybrid FIPS backend — RSA not in AWS-LC FIPS module

- **Location:** `mim-crypto/src/fips_backend.rs`
- **Behavior:** When `fips` is enabled, AES-256-GCM and SHA-256 use `aws-lc-rs`; RSA-PSS (NMBS) and RSA-OAEP (ZTDF key wrap) still use the `rsa` crate.
- **Limitation:** Even with `fips-validated`, the full crypto boundary is not a single FIPS 140-3 module.

### 1.4 Conformance / lab key material

- **Location:** `mim-crypto/src/keys.rs`, `fixtures/nmb-conformance-rsa.pk8`
- **Used by:** ADatP suite, labeling compliance checker, DCS demo scenario, HTTP server default config, ZTDF tests, most STANAG 4778 tests.
- **Limitation:** Deterministic 2048-bit RSA fixture (`nmb-conformance-key-1`). Not suitable for operational deployment.
- **Production path exists but is not default:** `NmbKeyRing::from_pkcs8_files()`, `NmbTrustStore::from_spki_pem_files()`.

### 1.5 NMBS and KAS keys collapsed in demos

- **Location:** `ZtdfPackage::create`, `DcsCrossDomainScenario::demo`, ADatP ZTDF suite
- **Behavior:** Same `VerifyingKey` is passed as both NMB signer and KAS public key; same `SigningKey` used for KAS unwrap.
- **Limitation:** No separation of label-signing authority from key-release authority in exercise paths.

### 1.6 No HSM or PKCS#11 integration

- **Location:** `mim-crypto/src/pki.rs` (PEM/PKCS#8 file and in-memory loading only)
- **Limitation:** Keys must be exported to PEM/DER; no hardware security module, no online key ceremony, no dual-control.

### 1.7 Fixed algorithms and key sizes

- **Behavior:** NMBS = RSA-PSS-SHA256; ZTDF = AES-256-GCM + RSA-OAEP-SHA256; generated keys = 2048-bit RSA.
- **Limitation:** No EC keys, no algorithm negotiation, no post-quantum profiles.

---

## 2. STANAG 4774 (Label syntax)

### 2.1 Label model subset

- **Location:** `mim-labeling/src/label.rs`, `mim-stanag4774/`
- **Implemented:** Policy identifier, classification, privacy mark, categories (tag name / type / values), creation and review timestamps.
- **Limitation:** Not all STANAG 4774 optional elements, national extensions, or compound category rules are modeled.

### 2.2 Two encodings only

- **Location:** `Stanag4774Format::{Xml, JsonStructured}`
- **Limitation:** No additional national wire formats beyond these two.

### 2.3 ADatP vector coverage is a subset

- **Location:** `mim-adatp-conformance/src/vectors.rs`
- **Behavior:** Table 17 tests use bundled `.nato` fixtures (6 Table 17 cases + 1 extra); Annex B and ACME suites add more.
- **Limitation:** Not exhaustive against the full ADatP-4774 catalog; passing the internal suite ≠ full NATO accreditation.

### 2.4 Demo national policies

- **Location:** `mim-spif` fixtures `capco-us-policy.xml`, `uk-demo.xml`; `LabelPolicy::uk_demo()`, `SpifPolicy::uk_demo()`
- **Limitation:** CAPCO-US and UK DEMO are **demonstration SPIF policies**, not live national policy corpora.

---

## 3. STANAG 4778 (Metadata binding)

### 3.1 Non-assertion bindings lack NMBS

- **Location:** `mim-stanag4778/src/bdo.rs` — `verify()` for `Embedded`, `Encapsulated`, `Detached`
- **Behavior:** Verifies payload digest (where applicable) and SPIF label validity only; **no cryptographic signature**.
- **Limitation:** Only `Assertion` method bindings are NMBS-signed. Embedded/encapsulated/detached are integrity + policy checks, not full NMBS profiles.

### 3.2 Cross-domain boundary requires assertion binding

- **Location:** `mim-dcs/src/transfer.rs`
- **Behavior:** Rejects embedded-only bindings at the guard with audit event `BindingReject`.
- **Limitation:** By design for DCS Level 2+; local MIM ingest may still use embedded labels without NMBS.

### 3.3 REST envelope — HTTP PUT only on server

- **Location:** `mim-transport-http/src/server.rs`
- **Implemented routes:** `PUT /mip4-ies/v1/objects`, `GET /health`
- **Limitation:** `GET /mip4-ies/v1/objects/{oid}`, filter GET, and DELETE are implemented on `ExchangeBroker` / `SecuredExchangeBroker` in `mim-transport` but **not exposed over HTTPS**.

### 3.4 SMTP header binding — library only

- **Location:** `mim-stanag4778/src/smtp_header.rs`
- **Limitation:** Create/verify API exists; no SMTP gateway, no email transport integration, no ADatP SMTP interop tests beyond structural use in runner.

### 3.5 Detached binding — no external label fetch

- **Location:** `BindingDataObject::detached(label, payload, label_uri)`
- **Limitation:** Stores a URI reference; does not fetch or verify label content at the URI.

---

## 4. ZTDF / OpenTDF / ACP-240

### 4.1 Static demo access policy

- **Location:** `mim-ztdf/src/manifest.rs` — `default_policy_b64()`
- **Behavior:** Fixed UUID and JSON body (`classification`, `releasableTo`, `dissem: coalition`) embedded as Base64 in every package.
- **Limitation:** Not sourced from a Policy Administration Point or KAS policy service; not evaluated at decrypt.

### 4.2 No Key Access Server (KAS) protocol

- **Location:** `ZtdfPackage::decrypt`, `manifest.encryption_information.key_wrap`
- **Behavior:** CEK is RSA-wrapped locally; unwrap uses a private key passed in-process.
- **Limitation:** No KAS HTTP/gRPC, no rewrap, no policy negotiation, no federated KMS (ACP-240 Supplement 5).

### 4.3 No ABAC enforcement at decrypt

- **Limitation:** Any holder of the KAS private key can decrypt regardless of subject attributes, clearance, or mission context.

### 4.4 OpenTDF manifest deviations / omissions

- **Location:** `mim-ztdf/src/manifest.rs`, `package.rs`
- **Implemented:** ZIP reference payload (`0.payload`), split encryption, `tdfSpecVersion` 1.0.0, handling assertion, inline `keyWrap`.
- **Missing vs OpenTDF spec:**
  - `keyAccess` objects with remote KAS endpoint URIs
  - `integrityInformation` block (integrity relies on NMBS assertion instead)
  - HTML TDF encoding profile
  - Streaming segment profile ( `isStreamable: true` is set but untested )
  - Official JSON schema validation against `opentdf/spec`
- **Limitation:** Internal ADatP ZTDF suite passes; external OpenTDF/ZTDF tool interoperability is unverified.

### 4.5 ACP-240 scope beyond ZTDF

- **Limitation:** ACP-240 Ed A architecture, full Access Control Framework (Supp. 1–2), and federated KMS (Supp. 5) are **not implemented**. This stack targets ZTDF encoding + STANAG 4774/4778 + DCS guard patterns only.

---

## 5. SPIF policy

### 5.1 Crate module doc marked placeholder

- **Location:** `mim-spif/src/lib.rs` — `//! Placeholder - see parser.rs`
- **Note:** Parser, validator, and registry are functional; the placeholder comment reflects incomplete SPIF administration productization, not an empty crate.

### 5.2 Custom XML parser — not full ISO 29008 / schema validation

- **Location:** `mim-spif/src/parser.rs`
- **Behavior:** Hand-rolled `quick-xml` event parser for a subset of SPIF elements (`securityPolicyId`, classifications, categories, validations).
- **Limitation:** No XSD validation, no full SPIF feature set (e.g. complex rule expressions, multiple policy versions, digital signatures on SPIF documents).

### 5.3 Bundled policy set only

- **Location:** `SpifRegistry::with_defaults()` — NATO 4774 reference, ACME, CAPCO-US demo, UK DEMO demo
- **Limitation:** No runtime SPIF distribution, no signed policy updates, no national policy workflow.

### 5.4 SPIF validation rules are simplified

- **Location:** `mim-spif/src/validator.rs`
- **Behavior:** Classification allow-list, per-category value allow-list, type match, and `required_any_of` validation rules.
- **Limitation:** Does not implement full SPIF constraint logic (permutations, prohibitions, national rule engines).

---

## 6. DCS and policy plane

### 6.1 Preset guards dominate demos

- **Location:** `CrossDomainGuard::preset_high_to_low()`, `preset_coalition()`; `DcsCrossDomainScenario::demo()`
- **Production path exists:** `CrossDomainGuard::from_spif_registry()` — not used by default scenarios.

### 6.2 Simplified downgrade logic

- **Location:** `mim-policy/src/pdp.rs` — `evaluate_cross_domain()`
- **Behavior:** When source classification exceeds target domain max, downgrades **classification only** to target max.
- **Limitation:** Does not strip releasability categories, handling caveats, or apply national downgrade rules (e.g. REL USA,GBR → USA only).

### 6.3 Policy Information Point is static

- **Location:** `mim-policy/src/pip.rs`
- **Limitation:** Subject attributes are caller-supplied; no LDAP, SAML, PKI certificate parsing, or mission system integration.

### 6.4 No XACML obligations / advices / combining algorithms

- **Location:** `mim-policy` PDP/PEP
- **Limitation:** Permit / deny / downgrade only; no policy language beyond stored domain rules and SPIF-derived registration.

### 6.5 Cross-domain policies are pairwise and manually registered

- **Location:** `PolicyStore`, `PolicyAdministrationPoint`
- **Limitation:** No dynamic policy federation, no central PAP service, no policy versioning beyond in-memory store.

---

## 7. Transport (MIP4-IES)

### 7.1 In-memory exchange broker

- **Location:** `mim-transport/src/broker.rs`
- **Limitation:** No persistence, replication, or crash recovery; state lost on process exit.

### 7.2 HTTP server partial API surface

- **Location:** `mim-transport-http/src/server.rs`
- **See also:** §3.3 — GET/DELETE not on HTTPS server.

### 7.3 Default trust store is conformance PKI

- **Location:** `HttpExchangeConfig::default()` → `HttpExchangeConfig::conformance()`
- **Limitation:** Out-of-the-box HTTP server trusts only the conformance NMBS key unless `with_config()` supplies production `NmbTrustStore`.

### 7.4 TLS test fixtures only in unit tests

- **Location:** `mim-transport-http/fixtures/test-server.crt`, `test-server.key`
- **Limitation:** No live TLS/mTLS end-to-end test in CI against a running server; mTLS client CA support exists (`with_client_ca`) but is not exercised in automated E2E.

### 7.5 Soft delete only

- **Location:** `ExchangeBroker::delete_object`
- **Behavior:** Marks OID inactive; instance remains in store.
- **Limitation:** No secure purge, no crypto-shredding of labeled payloads.

---

## 8. Audit

### 8.1 Demos use in-memory audit log

- **Location:** `AuditLog::memory()` in DCS scenario, labeling compliance checker, PEP tests
- **Limitation:** Records are not durable across restarts unless `FileAuditSink` is wired explicitly.

### 8.2 File sink is append-only JSONL — not WORM

- **Location:** `mim-audit/src/log.rs` — `FileAuditSink`
- **Limitation:** OS file permissions only; no write-once media, no remote tamper-evident storage, no SIEM auto-forwarding.

### 8.3 Audit NMBS signature uses fixed binding context

- **Location:** `mim-audit/src/chain.rs` — `sign_nmb_binding(signing_key, b"audit-record", &record_hash)`
- **Limitation:** Audit signatures are NMBS-shaped but use a static `"audit-record"` context byte string, not a STANAG 4774 label XML payload.

### 8.4 SIEM export is local JSON serialization

- **Location:** `AuditLog::export_siem()`
- **Limitation:** Returns JSON string; no syslog/CEF/OTLP shipping, no connector to Splunk/Elastic/QRadar.

---

## 9. MIM core, import, and compliance

### 9.1 Full MIM 5.1 model not loaded by default

- **Location:** `models/mim-full-5.1.json`, `MimStack::load()`
- **Limitation:** Compliance checker reports model coverage against manifest; full taxonomy coverage is not 100%.

### 9.2 Metadata taxonomy node not loaded

- **Location:** `mim-compliance/src/checker.rs` — `dimension_metadata()`
- **Message:** `"metadata types implemented; taxonomy node not yet loaded"`
- **Limitation:** MIM metadata dimension scores below full compliance until taxonomy is imported.

### 9.3 OWL import is a parser subset

- **Location:** `mim-import/src/owl.rs`
- **Behavior:** Extracts classes, labels, parents, and `owl:oneOf` enumerations from RDF/XML.
- **Limitation:** No OWL reasoning, no property axioms, no SHACL validation, no full JC3IEDM → MIM mapping.

### 9.4 mimworld fetch is best-effort HTTP

- **Location:** `mim-import/src/fetch.rs`
- **Limitation:** Simple `ureq` GET; no caching policy, no signature verification of downloaded ontologies, no offline mirror management.

---

## 10. Scenarios and CLI

### 10.1 All bundled scenarios are demos

- **Location:** `ainextgenc2/src/scenarios/`
- **Scenarios:** `AirDefenseRadarScenario::demo()`, `DcsCrossDomainScenario::demo()`, `TransportExchangeScenario::demo()`
- **Limitation:** Synthetic radar tracks and preset domains; not connected to live C2 systems or operational PKI.

### 10.2 Production PKI not wired into CLI defaults

- **Limitation:** Operators must explicitly configure `NmbKeyRing`, `NmbTrustStore`, `TlsIdentity`, and `HttpExchangeConfig` for coalition exercise tier (documented in NATO-STANAG-TECHNOLOGY.md but not automated).

### 10.3 Exit codes

- **Location:** `ainextgenc2/src/main.rs`
- **Behavior:** Exit `2` when MIM or labeling compliance not fully compliant; `--labeling` and `--adatp` flags run subset reports.
- **Note:** Use `cargo run -p ainextgenc2 -- --adatp` (not positional `adatp` argument).

---

## 11. Testing and accreditation gaps

| Gap | Impact |
|-----|--------|
| No external OpenTDF/ZTDF interop tests | Cannot claim vendor-neutral ACP-240 interoperability |
| No FIPS build in CI | Cannot claim FIPS 140-3 validated deployment |
| No live HTTPS E2E in CI | Transport security verified at unit level only |
| No formal guard accreditation artifacts | DCS guard is software-only evaluation engine |
| No penetration / fuzz testing of parsers | SPIF, STANAG 4774 XML, OWL parsers are hand-rolled |
| Labeling `FipsCrypto` passes on `ring` | Compliance score can be 12/12 while not FIPS-operational |

---

## 12. Suggested remediation priority

1. **OpenTDF/ZTDF schema validation** + external interop test vector
2. **KAS client stub** with ABAC gate before CEK unwrap
3. **Wire production PKI** into DCS scenario and HTTP server defaults (feature-flag conformance)
4. **HTTPS GET/DELETE** routes on `HttpExchangeServer`
5. **Category-aware downgrade** in PDP (releasability intersection with target domain)
6. **FIPS build** — pin `jobserver` or upgrade Rust to ≥ 1.85; evaluate RSA-in-FIPS-boundary
7. **WORM / SIEM connectors** for audit pipeline
8. **Full SPIF XSD validation** and signed policy distribution

---

## Related verification commands

```bash
# Internal conformance (does not cover items in this document)
cargo test -p mim-adatp-conformance
cargo test -p mim-labeling-compliance
cargo test --workspace

# Labeling report
cargo run -p ainextgenc2 -- --labeling

# ADatP report
cargo run -p ainextgenc2 -- --adatp

# FIPS build (currently fails on Rust 1.83)
cargo test -p mim-crypto --features fips
```
