# MIP4-IES FMN Readiness

Progress toward **FMN MIP4 Profile** / **MIP4-IES 4.4** REST binding conformance.

## REST service interface (MIP4-IES 4.4)

| Method | Path | Operation | Status |
|--------|------|-----------|--------|
| `PUT` | `/mip4-ies/v1/objects` | PutObject | Implemented (STANAG 4778 REST envelope + NMBS) |
| `GET` | `/mip4-ies/v1/objects/:oid` | GetByOID | Implemented (URL-encoded OID) |
| `GET` | `/mip4-ies/v1/objects?filter=…` | GetByFilter | Implemented (XPath subset) |
| `DELETE` | `/mip4-ies/v1/objects/:oid` | DeleteObject | Implemented (soft delete) |

Legacy query form remains supported: `?className=Target&propertyName=nameText&propertyValue=HOSTILE-1`.

## GetByFilter (XPath subset)

FMN-aligned filter query parameter:

```
GET /mip4-ies/v1/objects?filter=//Target[@nameText='HOSTILE-1']
```

Supported expressions:

- `//ClassName`
- `//ClassName[property='value']`
- `//ClassName[@property='value']`

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
| `mim-transport` | IES broker, REST parsing, XPath filter, STANAG envelope helpers |
| `mim-transport-http` | Axum router (`exchange_router`), TLS/mTLS server |

## Verification

```bash
cargo test -p mim-transport
cargo test -p mim-transport-http
cargo test -p ainextgenc2 transport
cargo run -p ainextgenc2 --example mip4_ies_exchange
```

## Remaining FMN gaps

| Gap | Priority |
|-----|----------|
| Official MIP4-IES XML message schemas on wire | High |
| Full XPath filter language | Medium |
| Replication / peer sync protocol | High |
| Persistent exchange store | High |
| MIP4-IES conformance test vectors | High |
| Live HTTPS E2E in CI | Medium |
| JSON-LD payload profile (MIP4 JSON-LD) | Medium |

See [REMAINING-STUBS-AND-LIMITATIONS.md](./REMAINING-STUBS-AND-LIMITATIONS.md).
