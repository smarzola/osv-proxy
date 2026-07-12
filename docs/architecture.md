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

Application state owns one reusable client set for all registry and artifact
traffic, so request routing reuses connection pools instead of constructing
clients on the install path. NuGet metadata and artifact delivery share the
same guarded client pool.

The runtime boundary owns process-wide registry/readiness ingress admission, aggregate install
egress, separate background-sync egress, overload propagation, and forced
shutdown cancellation. Permits live through response bodies, including
streamed artifacts. Dependency-free liveness remains deliberately outside
admission. The readiness boundary maps the configured live/local OSV
source into `/readyz`; local state comes from one read-only OSV-store API that
reuses the same generation, health, dataset-version, and staleness checks as
policy evaluation. These boundaries do not create alternate routing or
artifact-delivery paths.

Proxy-mode artifact delivery enforces an egress boundary before contact. It
permits public HTTPS CDN origins plus exact configured origins for the artifact's
ecosystem and explicit operator-trusted origins. DNS answers containing a
loopback, private, link-local, or otherwise non-public address are rejected
unless that exact hostname origin was trusted. Artifact delivery ignores system
proxy settings and does not follow upstream redirects. NuGet service-index and
registration-page follow-up requests use this boundary before parsing their
bounded JSON bodies because those URLs are also metadata-derived.

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
optional. Request-time SQLite reads, version/range evaluation, and Maven XML
deserialization run in separate bounded blocking pools. Local batch checks load
all ranges and ordered events once per ecosystem/package, then evaluate every
requested version in memory. Sync runs are serialized per SQLite path, attempt
each requested ecosystem independently, and retain successful generations when
another ecosystem fails. Background mode retries only failed ecosystems with
bounded exponential backoff before returning to the normal interval.

## Upstream Body Bounds

All registry metadata and OSV HTTP responses are checked against
`Content-Length` when present and against cumulative bytes received while
streaming. Current ceilings are:

| Response | Limit |
| --- | ---: |
| npm package metadata | 32 MiB |
| PyPI Simple root / project | 128 MiB / 32 MiB |
| Cargo sparse entry | 16 MiB |
| Go version list / info | 4 MiB / 1 MiB |
| NuGet V3 JSON | 32 MiB |
| RubyGems version metadata / versions index / compact info | 16 MiB / 64 MiB / 16 MiB |
| Maven POM / metadata | 1 MiB / 2 MiB |
| Live OSV API response | 64 MiB |
| OSV dump document | 256 MiB |

OSV `all.zip` downloads stream to an unnamed temporary file rather than an
in-memory buffer. The compressed archive is capped at 4 GiB, one expanded JSON
entry at 16 MiB, the archive at one million entries, and cumulative expanded
JSON at 8 GiB. A bound violation fails the affected sync before generation
activation.

## Future Boundaries

Metadata cache, S3 artifact cache, MongoDB-compatible advisory storage, and an
audit sink are possible future components. They are not implemented current
components. If introduced, they must preserve the metadata/artifact policy
recheck and generation-readiness invariants.
