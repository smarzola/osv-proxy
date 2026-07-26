# Mongolino Integration

mongolino is a possible future backend for synchronized OSV advisory records. It
should be treated as MongoDB-compatible infrastructure, not as a separate
`osv-proxy` backend or config shape.

The active OSV store is SQLite, configured through
`policy.osv.local.sqlite_path`. Runnable examples should use SQLite and
`osv-proxy osv sync --config <path>`. Request-path remote OSV queries are not
supported.

## Future Contract

- If MongoDB-compatible storage is added later, use one store interface for
  mongolino and MongoDB.
- Keep package policy independent of the storage server behind that interface.
- Preserve the current SQLite semantics: advisory metadata, optional raw
  advisory JSON retention, normalized affected packages, exact versions, range
  events, and sync state.
- Preserve full-advisory generation readiness and normalized severity inputs.
- Preserve transactional content revisions used by metadata cache identity.
- Preserve the invariant that metadata generation and artifact serving both
  evaluate current policy.
