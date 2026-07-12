# MIP4-IES accreditation fixtures

FMN-aligned internal accreditation vectors for `mim-mip4-conformance`.

## Bundled vectors

| File | Format | Purpose |
|------|--------|---------|
| `nato-mip4-target.xml` | MIM XML | NATO-style Target instance (interop baseline) |
| `nato-mip4-target.json` | MIM JSON | Same Target as plain JSON instance |
| `nato-mip4-target.jsonld` | JSON-LD | Same Target in MIP4-IES JSON-LD wire profile |

## NATO-provided vectors (drop-in)

When NATO ships official MIP4-IES accreditation test vectors, add them under
`fixtures/nato-provided/` and register each file in `src/vectors.rs`. The
`run_accreditation_vectors()` runner will parse, validate, and exercise broker
CRUD without further code changes.
