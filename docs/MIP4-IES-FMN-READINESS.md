# MIP4-IES FMN Readiness

Progress toward **FMN MIP4 Profile** / **MIP4-IES 4.4** REST binding conformance and accreditation.

**Precise compliance status:** [STATUS.md](./STATUS.md) — automated suite reports **100% FULLY COMPLIANT** (140/140 checks, verified 2026-07-11).

## REST service interface (MIP4-IES 4.4)

| Method | Path | Operation | Status |
|--------|------|-----------|--------|
| `PUT` | `/mip4-ies/v1/objects` | PutObject | Implemented (STANAG 4778 REST envelope + NMBS) |
| `GET` | `/mip4-ies/v1/objects/:oid` | GetByOID | Implemented (URL-encoded OID) |
| `GET` | `/mip4-ies/v1/objects?filter=…` | GetByFilter | Implemented (XPath subset + pagination) |
| `DELETE` | `/mip4-ies/v1/objects/:oid` | DeleteObject | Implemented (soft delete) |
| `GET` | `/mip4-ies/v1/sync?since=N` | Replication sync | Implemented (change journal) |

Legacy query form remains supported: `?className=Target&propertyName=nameText&propertyValue=HOSTILE-1`.

## Wire formats and content negotiation

| Format | Media type | Direction |
|--------|------------|-----------|
| MIM JSON | `application/mim+json` | Default for REST JSON responses |
| MIM XML | `application/mim+xml` | Select via `Accept: application/mim+xml` on GET |

All responses include `MIM-Version: 5.1.0`.

PutObject envelope payload may contain JSON or XML MIM instance bodies; format is detected from payload structure or `Content-Type` / `X-MIM-Payload-Format`.

## GetByFilter (XPath subset)

FMN-aligned filter query parameter:

```
GET /mip4-ies/v1/objects?filter=//Target[@nameText='HOSTILE-1']&limit=10&offset=0
```

Supported expressions:

- `//ClassName`
- `//ClassName[property='value']`
- `//ClassName[@property='value']`

Pagination: `limit` and `offset` query parameters; response includes `count` (returned) and `total` (matched before pagination).

## Replication sync

Peer nodes poll the change journal:

```
GET /mip4-ies/v1/sync?since=0
```

Returns `{ latestSequence, entries[] }` with PutObject/DeleteObject journal records.

## Persistence

File-backed exchange snapshots via `mim_transport::FileExchangeStore`:

- Primary snapshot: `exchange.json` (instances, inactive OIDs, journal, sequence)
- Append-only audit: `exchange.journal.jsonl`

## MIM XML exchange schema

- Serialize/deserialize: `mim_runtime::Serializer` with `SerializationFormat::Xml`
- XSD validation: `mim_runtime::validate_exchange_xsd()` (bundled `schemas/mim-exchange.xsd`)

## OID path encoding

OIDs such as `urn:uuid:…` must be **percent-encoded** in path segments:

```
GET /mip4-ies/v1/objects/urn%3Auuid%3A550e8400-e29b-41d4-a716-446655440000
```

Use `mim_transport::encode_oid_for_path()`.

## Security binding (coalition profile)

- PutObject requires STANAG 4778 REST envelope with NMBS assertion
- `X-NATO-Confidentiality-Label` header must match envelope label XML
- `SecuredExchangeBroker` enforces PEP clearance on read/write/delete
- HTTPS server selects NMBS verifying key by `keyId` from trust store

## Crates

| Crate | Role |
|-------|------|
| `mim-runtime` | MIM XML serialize/deserialize, exchange XSD |
| `mim-transport` | IES broker, journal, persistence, wire media types |
| `mim-transport-http` | Axum router (`exchange_router`), content negotiation |
| `mim-mip4-conformance` | Accreditation test vectors (`--mip4`) |

## Dimensional accreditation scorecard

`cargo run -p ainextgenc2 -- --mip4` evaluates **seven FMN dimensions**. Each dimension must score **≥95%** for accreditation readiness; the current automated suite scores **100%** on all seven.

| Dimension | Scope | Current |
|-----------|--------|---------|
| REST operations | CRUD, sync, pagination, REST route parsing | **100%** |
| REST binding | Media types, JSON-LD, XPath, MIM-Version, envelopes | **100%** |
| Message schemas | JSON/XML/JSON-LD roundtrip, XSD, JSON schema validation | **100%** |
| Replication | Journal, sync, `ReplicationAgent`, persistence | **100%** |
| MIM semantics | Validator, registry, PutObject validation | **100%** |
| FMN security | STANAG 4778 envelopes, PEP clearance, secured sync | **100%** |
| Accreditation | NATO-style fixtures, interop vectors, full-stack | **100%** |

**Result:** **140/140 checks pass** — exit code 0, **FULLY COMPLIANT** (verified 2026-07-11).

Operational pilot gaps (JSON-LD wire profile, live HTTPS E2E, NATO-provided vectors) remain; see [Remaining FMN gaps](#remaining-fmn-gaps) and [REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md).

## Verification

```bash
cargo test -p mim-runtime -p mim-transport -p mim-transport-http -p mim-mip4-conformance
cargo run -p ainextgenc2 -- --mip4
cargo run -p ainextgenc2 --example mip4_ies_exchange
```

## Remaining FMN gaps

| Gap | Priority |
|-----|----------|
| Official MIP4-IES JSON-LD profile on wire | Medium |
| Full XPath filter language | Medium |
| Peer-to-peer replication protocol (beyond journal poll) | Medium |
| Live HTTPS E2E in CI | Medium |
| NATO-provided MIP4-IES accreditation test vectors | High |

See [REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md).
