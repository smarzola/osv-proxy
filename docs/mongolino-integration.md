# Mongolino Integration

mongolino is a possible future local store for synchronized OSV `MAL-*`
records. It should be treated as MongoDB-compatible infrastructure, not as a
separate `osv-proxy` backend or config shape.

The active config does not expose a local malicious-record store. Until that
surface exists, runnable examples should use live OSV checks or an explicit
`policy.osv.api_url` override for tests.

## Future Contract

- Use one MongoDB-compatible store interface for mongolino and MongoDB.
- Keep package policy independent of the storage server behind that interface.
- Store only normalized OSV `MAL-*` records as blocking inputs.
- Preserve the invariant that metadata generation and artifact serving both
  evaluate current policy.
