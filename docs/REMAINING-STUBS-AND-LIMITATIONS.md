# Remaining Stubs and Limitations

Inventory of known gaps, demo-only paths, partial implementations, and operational limitations in the AINextGenC2 / MIM labeling stack after the SOTA follow-up branch (`cursor/sota-spif-dcs-stanag-mim-0965`).

This document complements [NATO-STANAG-SYSTEM.md](./NATO-STANAG-SYSTEM.md), [NATO-STANAG-TECHNOLOGY.md](./NATO-STANAG-TECHNOLOGY.md), and [SOTA-IMPROVEMENTS.md](./SOTA-IMPROVEMENTS.md). Items here are **not** tracked as failing ADatP or labeling compliance tests unless noted.

---

## Summary

| Area | Lab / exercise | Operational pilot | Classified accredited |
|------|----------------|-------------------|------------------------|
| STANAG 4774/4778 core | Ready | Partial | Not ready |
| ZTDF / ACP-240 Supp. 3–4 | Ready (encoding) | Partial (no KAS/ABAC) | Not ready |
| ACP-240 full (Ed A + Supp. 5) | Partial | Not ready | Not ready |
| DCS cross-domain | Ready (config file) | Partial | Not ready |
| MIP4-IES transport | Ready (dimensional ≥95%) | Partial | Not ready |
| Crypto / PKI | Conformance keys; FIPS build verified | PKI loaders exist; not default | RSA outside FIPS module |
| MIM full manifest | 820 OWL attributes imported | Partial | Not accredited |
| Audit | In-memory / file JSONL | Partial | WORM / HSM not implemented |

---

## Closed in SOTA follow-up (no longer limitations)

| Item | Resolution |
|------|------------|
| SPIF XSD validation | `mim-spif/src/xsd.rs` + vendored ISO/XML-SPIF schemas |
| STANAG 4774 label XSD | `mim-stanag4774/src/xsd.rs` + bundled schema; codec XSD gate |
| Hardcoded DCS guard | `config/dcs-coalition.toml` + `DcsConfig` API |
| Category-only downgrade | Category-aware releasability intersection in PDP |
| STANAG 4774 alternative labels / colour / marking | Extended model + XML round-trip |
| STANAG 4778 NMBS profiles / detached fetch | `*_with_nmb()`, `FileDetachedLabelResolver` |
| MIM metadata taxonomy missing | Core seed + compliance dimension |
| MIM full manifest attributes (4 only) | Regenerated `mim-full-5.1.json` with 820 OWL attributes |
| MIP4-IES XML wire + XSD | `mim-runtime` XML deserialize + `validate_exchange_xsd` |
| MIP4-IES persistence + journal | `FileExchangeStore` + `GET /mip4-ies/v1/sync` |
| MIP4-IES conformance runner | `mim-mip4-conformance` + `ainextgenc2 --mip4` |
| FIPS build blocked on Rust 1.83 | `rust-toolchain.toml` 1.85 + `SecureRandom` import fix |
| mimworld.org OWL 404 | DISO mirror + bundled `models/ontology/JC3IEDM.owl` fallback |

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

- **Implemented:** Policy, classification, privacy mark, categories, alternative labels, colour, marking data, timestamps, XSD validation.
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

## 4. ZTDF / OpenTDF / ACP-240 *(out of scope for SOTA follow-up)*

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
- **Limitation:** No full ISO 29008 feature set (complex rule expressions, signed SPIF distribution).

---

## 6. DCS and policy plane

### 6.1 Policy Information Point is static

- **Limitation:** Subject attributes are caller-supplied; no LDAP/SAML integration.

### 6.2 No XACML obligations / combining algorithms

- **Limitation:** Permit / deny / downgrade only.

---

## 7. Transport (MIP4-IES)

### 7.1 Persistent exchange store (implemented)

- **Implemented:** `FileExchangeStore` snapshots (`exchange.json`) + append-only `exchange.journal.jsonl`
- **Limitation:** No distributed consensus or multi-node replication protocol beyond journal poll

### 7.2 HTTP server — REST CRUD + wire formats (FMN progress)

- **Implemented:** Full CRUD, XPath filter, pagination, `MIM-Version` header, `application/mim+json` / `application/mim+xml`, replication sync
- **See:** [MIP4-IES-FMN-READINESS.md](./MIP4-IES-FMN-READINESS.md)
- **Remaining:** Official MIP4 JSON-LD profile, full XPath, NATO-provided accreditation vectors, live HTTPS E2E in CI

### 7.3 Default trust store is conformance PKI

- **Limitation:** HTTP server trusts conformance NMBS key unless configured.

---

## 8. Audit

### 8.1 Demos use in-memory audit log

- **Limitation:** Not durable unless `FileAuditSink` is wired.

### 8.2 File sink is append-only JSONL — not WORM

- **Limitation:** No write-once media or SIEM auto-forwarding.

---

## 9. MIM core, import, and compliance

### 9.1 OWL import is a parser subset

- **Implemented:** Classes, properties, enumerations; 820 attributes from bundled JC3IEDM OWL; XSD range → representation term mapping.
- **Limitation:** No OWL reasoning, SHACL, or full JC3IEDM → MIM accreditation mapping (~1748 OWL properties; ~820 imported where domain matches taxonomy).

### 9.2 Authoritative MIM 5.1 OWL not bundled

- **Limitation:** Bundled ontology is JC3IEDM v3.0 (DISO/Vistology); mimworld MIM 5.1 OWL remains unavailable at published URLs.

---

## 10. Scenarios and CLI

### 10.1 Bundled scenarios are demos

- **Limitation:** Synthetic radar tracks; not connected to live C2 systems.

---

## 11. Suggested remediation priority

1. **KAS client stub** with ABAC gate before CEK unwrap *(deferred)*
2. **OpenTDF/ZTDF schema validation** + external interop *(deferred)*
3. **Wire production PKI** into DCS scenario and HTTP server defaults (feature-flag conformance)
4. **MIP4-IES JSON-LD wire profile** and NATO accreditation test vectors
5. **WORM / SIEM connectors** for audit pipeline
6. **Signed SPIF distribution** workflow
7. **Authoritative MIM 5.1 OWL** when MIP republishes mimworld downloads

---

## Related verification commands

```bash
cargo test --workspace
cargo test -p mim-stanag4774
cargo test -p mim-crypto --features fips
cargo run -p mim-import -- --source bundled:jc3iedm --output models/mim-full-5.1.json --merge models/mim-core-5.1.json
cargo run -p ainextgenc2 -- --labeling
cargo run -p ainextgenc2 -- --adatp
cargo run -p ainextgenc2 -- --mip4
```
