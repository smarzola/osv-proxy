# Understand the architecture

This document describes the runtime boundaries that preserve policy
correctness and request-path performance. It is intended for contributors and
operators who need to evaluate failure modes or deployment behavior.

## Request flow

`osv-proxy` uses one canonical artifact and policy model for all supported
registries:

```text
package manager
      |
      v
router and admission control
      |
      +-- metadata GET
      |      |
      |      v
      |  revision-aware filtered metadata cache -- hit --> response
      |      |
      |     miss
      |      |
      |  registry adapter --> canonical artifacts --> policy
      |                                           |
      |                                           v
      |                                  local SQLite OSV
      |                                           |
      |                                  filter and serialize
      |
      +-- package-file GET --> canonical artifact --> current policy
                                                       |
                                            redirect or stream bytes
```

Each adapter normalizes registry data into an `Artifact` with an ecosystem,
package name, version, filename, upstream URL, publication time, and available
hashes. The policy engine therefore evaluates the same model for metadata and
package-file requests.

Metadata adapters evaluate artifacts in batches, remove denied versions, and
rewrite retained download URLs through `osv-proxy`. A package-file route
rebuilds the requested artifact and evaluates current policy before it
redirects or contacts the upstream file origin.

## Application state

One application state owns the following shared resources:

- Registry clients and their connection pools.
- The process-wide filtered metadata cache.
- The local SQLite OSV checker.
- Ingress, install-path egress, background-sync egress, and blocking-work
  limits.

NuGet metadata and package-file routes use the same guarded client pool. A
streamed response retains its ingress and egress permits until the body
finishes or the request is canceled.

## OSV data boundary

The policy engine reads OSV findings from local SQLite only. Install requests
do not call the OSV network.

The database stores one active generation per ecosystem. A bootstrap imports
an archive and source-timestamp catch-up into a staging generation, then
activates the generation atomically. A failed bootstrap leaves the previous
generation active. Incremental sync changes the active generation in one
transaction.

The local checker performs indexed reads and evaluates exact versions and OSV
ranges. Batch checks load range records once for each ecosystem and package,
then evaluate requested versions in memory. Separate bounded blocking pools
isolate SQLite work and Maven XML parsing from asynchronous request workers.

Each ecosystem has a durable content revision. A sync transaction advances the
revision only when normalized advisory content changes. Metadata cache keys
include this revision, so a request that starts after the commit cannot hit a
response filtered against older OSV data.

## Metadata cache boundary

The process-local cache stores complete HTTP responses after upstream fetch,
parsing, policy evaluation, filtering, URL rewriting, and serialization.

The cache admits only supported policy-filtered metadata `GET` routes. It does
not admit the following responses:

- Package files.
- Health or readiness.
- Static discovery or client-configuration documents.
- Non-success responses.
- Overload or transient policy-error responses.
- Bodies larger than the configured entry limit.

The key includes the ecosystem, committed OSV content revision, exact path and
query, and material representation, conditional, and range headers. Identical
misses share one fill. A semaphore bounds distinct fills.

An indexed hash map and intrusive least-recently-used list provide O(1) hit and
eviction maintenance. Weighted capacity, maximum entry size, and time to live
bound retention. Package-age eligibility transitions can expire an entry
before its configured maximum lifetime.

Fill state retains a terminal result. If a fill leader is canceled, existing
and late waiters observe abandonment and retry instead of waiting
indefinitely.

## Request budgets

The runtime enforces three independent limits:

- The ingress limit covers registry requests and `/readyz`.
- The install-path egress limit covers registry metadata and package-file
  requests.
- The background-sync egress limit prevents OSV synchronization from consuming
  install-path capacity.

`/healthz` remains outside ingress admission so a saturated process can still
report liveness. Queue timeouts return HTTP `503` with `Retry-After: 1`.

SIGINT and SIGTERM stop new connections and give active requests 30 seconds to
drain. Forced cancellation can take up to one additional second.

## Outbound security boundary

Before proxy-mode file delivery connects, it validates the destination URL and
resolved addresses. It permits public HTTPS content-delivery origins and exact
origins configured for that ecosystem. You can also add exact origins through
`artifacts.trusted_origins`.

Private, loopback, link-local, or other non-public addresses require an exact
trusted origin. An origin configured for one ecosystem cannot authorize a
different ecosystem or port. Package-file requests ignore system HTTP proxy
settings and reject upstream redirects.

NuGet applies the same checks to registration resources discovered from the
service index and registration pages.

## Upstream response limits

The proxy checks declared and streamed body sizes. The following table lists
the current limits:

| Response | Maximum size |
| --- | ---: |
| Cargo sparse record | 16 MiB |
| Go version list | 4 MiB |
| Go version information | 1 MiB |
| Maven POM | 1 MiB |
| Maven metadata | 2 MiB |
| npm package metadata | 32 MiB |
| NuGet V3 JSON | 32 MiB |
| PyPI Simple root | 128 MiB |
| PyPI Simple project | 32 MiB |
| RubyGems versions index | 64 MiB |
| RubyGems version metadata or compact info | 16 MiB |
| OSV dump document | 256 MiB |

An OSV `all.zip` download streams to a temporary file. The compressed archive
is limited to 4 GiB, one expanded JSON entry to 16 MiB, the archive to one
million entries, and total expanded JSON to 8 GiB. A violation fails the
affected sync before activation.

## Readiness boundary

`/readyz` uses the same generation, dataset-version, health, and staleness
checks as policy evaluation. Vulnerability blocking requires a complete
all-advisory generation. An upgraded malicious-only database remains
incomplete until bootstrap succeeds.

The server starts background synchronization without waiting for it. A
healthy, non-stale database remains ready while an incremental update runs.
Missing, incomplete, unhealthy, or stale data keeps readiness false and
follows the configured fail-closed policy.

## External responsibilities

Use a gateway or reverse proxy for TLS, authentication, client rate limiting,
and edge access control. `osv-proxy` deliberately does not implement those
internet-edge responsibilities.

S3 artifact caching, MongoDB-compatible advisory storage, and a structured
audit sink are not implemented. Any future implementation must preserve the
metadata revision and package-file recheck invariants.
