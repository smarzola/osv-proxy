# Mongolino Integration

mongolino is a possible future backend for synchronized OSV `MAL-*` records. It
should be treated as MongoDB-compatible infrastructure, not as a separate
`osv-proxy` backend or config shape.

The active local malicious store is SQLite, configured through
`policy.osv.source: local` and `policy.osv.local.sqlite_path`. Runnable local
mode examples should use SQLite and `osv-proxy malicious sync --config <path>`.
Live mode remains available with `policy.osv.source: live`.

## Future Contract

- If MongoDB-compatible storage is added later, use one store interface for
  mongolino and MongoDB.
- Keep package policy independent of the storage server behind that interface.
- Preserve the current SQLite semantics: advisory metadata, optional raw
  advisory JSON retention, normalized affected packages, exact versions, range
  events, and sync state.
- Store only OSV `MAL-*` records as blocking inputs.
- Preserve the invariant that metadata generation and artifact serving both
  evaluate current policy.
