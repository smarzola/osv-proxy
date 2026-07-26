# Evaluate MongoDB-compatible OSV storage

MongoDB-compatible OSV storage, including mongolino, is not implemented.
Production configuration and runnable examples must use local SQLite through
`policy.osv.local.sqlite_path`.

If the project adds MongoDB-compatible storage, it should use one storage
interface for MongoDB and mongolino rather than a product-specific backend.
The implementation must preserve the following SQLite behavior:

- Complete all-advisory generation readiness.
- Transactional generation activation.
- Transactional content revisions for metadata cache identity.
- Advisory metadata and normalized exact-version and range lookups.
- Optional raw advisory JSON retention.
- Deterministic severity inputs.
- Identical policy behavior for metadata and package-file requests.

Until that contract is implemented and tested, MongoDB-compatible fields must
remain absent from the public configuration schema.
