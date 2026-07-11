# Architecture

`osv-proxy` is currently one Rust crate with ecosystem adapters around one
canonical artifact and policy model.

## Current Components

```text
server/router
  npm metadata + tarball routes
  PyPI Simple + file routes
  Cargo sparse index + crate routes
  Go list/info/mod/zip routes
  NuGet service/registration/flat-container/package routes
  Maven metadata + artifact routes
        |
        v
ecosystem adapters -> canonical Artifact
        |
        v
policy
  exact allowlist and OSV bypass
  OSV malicious/vulnerability evaluation
  manual blocklist
  minimum age and missing-time behavior
        |
        +-- live OSV client
        |     paginated query/batch + bounded detail hydration
        |
        +-- local SQLite OSV store
              generation-scoped advisories and affected occurrences
              exact versions, ranges/events, selected severity/error
              bootstrap catch-up + incremental/background sync
        |
        v
artifact delivery
  redirect | plain streaming proxy
```

All adapters normalize registry data into `Artifact { ecosystem, name,
version, filename, upstream_url, published_at, hashes }`. Supported ecosystems
are npm, PyPI, crates.io, Go, NuGet, RubyGems, and Maven. Package names and versions are
normalized according to their registry before policy evaluation.

Metadata filtering evaluates batches of canonical artifacts. Retained download
URLs point back through `osv-proxy`. Direct artifact routes rebuild the exact
artifact and re-run policy before redirecting or fetching upstream bytes.

## OSV Boundary

The policy engine consumes OSV findings and does not depend on whether they came
from live HTTP or local SQLite. Live batch checks preserve input cardinality,
deduplicate advisory IDs, paginate, and hydrate at most 16 details concurrently.
Local request handling performs indexed reads only and makes no OSV network
call.

The local store uses one active generation per ecosystem. Bootstrap imports an
archive plus source-timestamp catch-up into staging and activates it atomically;
failed imports never expose partial data. Existing malicious-only databases are
version 0 and cannot satisfy vulnerability-enabled readiness. Raw JSON remains
optional.

## Future Boundaries

Metadata cache, S3 artifact cache, MongoDB-compatible advisory storage, and an
audit sink are possible future components. They are not implemented current
components. If introduced, they must preserve the metadata/artifact policy
recheck and generation-readiness invariants.
