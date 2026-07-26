# Architecture

`osv-proxy` is currently one Rust crate with ecosystem adapters around one
canonical artifact and policy model.

## Current Components

```text
server/router
  |
  +-- supported metadata GET
  |       |
  |       v
  |   revision-aware filtered metadata cache -- hit --> client
  |       |
  |      miss
  |       |
  +-------+-- ecosystem adapter -> canonical Artifact -> policy
  |
  +-- artifact GET ------------> canonical Artifact -> policy
                                                        |
                         +------------------------------+
                         |
                         +-- local SQLite OSV store
                         |     generations + affected records
                         |     exact versions + ranges + severity
                         |     transactional content revisions
                         |
                         +-- metadata: filter + serialize + cache
                         |
                         +-- artifact: redirect | streaming proxy
```

All adapters normalize registry data into `Artifact { ecosystem, name,
version, filename, upstream_url, published_at, hashes }`. Supported ecosystems
are npm, PyPI, crates.io, Go, NuGet, RubyGems, and Maven. Package names and versions are
normalized according to their registry before policy evaluation.

Metadata filtering evaluates batches of canonical artifacts. Retained download
URLs point back through `osv-proxy`. Direct artifact routes rebuild the exact
artifact and re-run policy before redirecting or fetching upstream bytes.

Application state owns one reusable client set and one metadata cache for all
registry traffic, so request routing reuses connection pools and filtered
representations. NuGet metadata and artifact delivery share the same guarded
client pool.

The runtime boundary owns process-wide registry/readiness ingress admission, aggregate install
egress, separate background-sync egress, overload propagation, and forced
shutdown cancellation. Permits live through response bodies, including
streamed artifacts. Dependency-free liveness remains deliberately outside
admission. The readiness boundary maps local OSV state into `/readyz` through
one read-only OSV-store API that
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

The policy engine consumes findings from local SQLite only. Request handling
performs indexed reads and makes no OSV network call.

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

Each ecosystem's `sync_state` row carries a durable content revision. A sync
advances it in the same transaction that makes changed advisory content
visible. Metadata cache keys include that revision, so requests beginning
after the commit cannot hit an older filtered representation. No-op and failed
syncs leave the revision unchanged.

## Metadata Cache Boundary

Only supported policy-filtered metadata GET routes enter the process-local
cache. Values are complete immutable HTTP representations produced after
upstream fetch, parsing, SQLite policy evaluation, filtering, URL rewriting,
and serialization. Direct artifacts and static discovery/configuration routes
remain outside it.

Hits use indexed O(1) lookup and LRU maintenance. Weighted capacity, maximum
entry size, TTL, and distinct-fill concurrency are validated configuration.
Identical misses share one fill. Policy-age transitions cap entry lifetime, and
transient policy/revision failures use bounded singleflight without retention.
Material request headers and the exact path/query participate in identity.

## Upstream Body Bounds

All registry metadata and OSV dump responses are checked against
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
| OSV dump document | 256 MiB |

OSV `all.zip` downloads stream to an unnamed temporary file rather than an
in-memory buffer. The compressed archive is capped at 4 GiB, one expanded JSON
entry at 16 MiB, the archive at one million entries, and cumulative expanded
JSON at 8 GiB. A bound violation fails the affected sync before generation
activation.

## Future Boundaries

S3 artifact cache, MongoDB-compatible advisory storage, and an audit sink are
possible future components. They are not implemented current components. If
introduced, they must preserve the metadata/artifact policy recheck and
generation-readiness invariants.
