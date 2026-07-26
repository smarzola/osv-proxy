# Plan performance and startup

`osv-proxy` keeps OSV evaluation local and caches complete filtered metadata
responses in process. Package install requests use the registry upstream and
local SQLite; they do not depend on OSV network latency.

Use the measurements on this page for relative planning, not as service-level
objectives. Public registry load, package cardinality, hardware, cache state,
and policy configuration all affect results.

## Read the measurement context

The measurements were captured on 2026-07-12 on a macOS arm64 development
machine.

The metadata table compares the same proxy route with OSV checks disabled and
with local SQLite checks enabled. These requests exercised complete upstream
fetch, parsing, policy evaluation, filtering, and serialization. They did not
measure a filtered metadata cache hit.

Response sizes can differ because policy removes denied versions. The added
local-path column is therefore more useful than comparing total response
latency across ecosystems.

## Compare metadata fill latency

| Ecosystem and route | Policy disabled p50 | Local OSV p50 | Added local path |
| --- | ---: | ---: | ---: |
| Cargo serde | 10.3 ms | 11.0 ms | 0.7 ms |
| Cargo tokio | 17.0 ms | 21.1 ms | 4.1 ms |
| Go `github.com/gin-gonic/gin` | 19.4 ms | 26.3 ms | 6.9 ms |
| Go `github.com/pkg/errors` | 12.5 ms | 15.3 ms | 2.8 ms |
| Maven commons-lang3 | 62.9 ms | 91.6 ms | 28.7 ms |
| npm lodash | 19.1 ms | 21.5 ms | 2.4 ms |
| npm React | 124.5 ms | 128.1 ms | 3.6 ms |
| NuGet Newtonsoft.Json | 135.2 ms | 269.1 ms | 133.9 ms |
| NuGet logging abstractions | 136.6 ms | 156.0 ms | 19.4 ms |
| PyPI Django | 22.4 ms | 60.8 ms | 38.4 ms |
| PyPI urllib3 | 8.4 ms | 9.2 ms | 0.8 ms |
| RubyGems nokogiri | 25.3 ms | 66.2 ms | 40.9 ms |
| RubyGems rack | 9.1 ms | 30.7 ms | 21.6 ms |

Local overhead grows with metadata size and the number of versions or files
that policy must evaluate. High-cardinality NuGet, RubyGems, PyPI, and Maven
responses perform more work than small Cargo, Go, or npm responses.

## Use the filtered metadata cache

A supported metadata cache hit skips all fill work:

- Upstream fetch.
- Protocol parsing.
- SQLite policy lookups.
- Filtering and URL rewriting.
- Serialization.

The cache uses O(1) lookup and least-recently-used maintenance. Its defaults
are:

| Setting | Default |
| --- | ---: |
| Weighted capacity | 128 MiB |
| Maximum response body | 16 MiB |
| Maximum time to live | 5 minutes |
| Concurrent distinct fills | 8 |

Identical misses share one fill. Package-age transitions can shorten an
entry's lifetime. A content-changing OSV sync advances the ecosystem revision,
so new requests cannot hit entries created from older advisory content.

The weighted cache budget includes keys, headers, and bodies, but not every
allocator or runtime cost. Do not treat it as a process resident-memory limit.

No cache-hit latency or throughput number is published yet. Re-run the
benchmark matrix before using a cache-hit estimate for capacity planning.

## Review the resource measurements

| Measurement | Result |
| --- | ---: |
| Release binary | 9.886 MiB |
| Release archive | 4.319 MiB |
| `/healthz` sequential p50 | 0.147 ms |
| `/healthz`, 128 persistent connections | 124k requests/sec, 0 errors |
| Fresh idle resident memory | 9.0 MiB |
| Resident memory after health load | 13.7 MiB |
| Resident memory after a large React metadata fill | 81.6 MiB |
| Fresh all-ecosystem OSV sync | 21.37 seconds |
| Fresh sync peak resident memory | 220.6 MiB |
| Full synchronized SQLite database | 194.85 MiB |

The health test used persistent HTTP/1.1 connections and serves as a server
smoke measurement, not a capacity limit. Large metadata fills increase
transient memory because the proxy must parse and filter the upstream
document.

The resident-memory measurements do not include a populated metadata cache.
Add the configured cache budget and deployment-specific runtime overhead when
you plan process limits.

## Preseed the database for fast startup

Prepare the SQLite database before launch when startup must not depend on OSV
network availability:

```sh
mkdir -p /var/lib/osv-proxy

osv-proxy config validate --config /etc/osv-proxy/osv-proxy.yaml
osv-proxy osv sync --config /etc/osv-proxy/osv-proxy.yaml

exec osv-proxy serve --config /etc/osv-proxy/osv-proxy.yaml
```

A complete, non-stale database can serve immediately. The default background
task can refresh it while requests continue to read the last committed
generation.

Use one of the following preseed patterns:

- Bake a completed SQLite file into an image that you rebuild on a controlled
  schedule.
- Run `osv sync` in a deployment init job and place the database on a
  persistent volume before the server starts.
- Publish the binary, validated configuration, and synchronized database as
  one deployment artifact.

Do not copy the database while a sync process writes it. Wait for the sync to
finish, then package or mount the completed file.

## Choose synchronization ownership

Keep `background_sync: true` when the server process should own OSV freshness.
It starts an update immediately and starts each later cycle one hour after the
previous successful cycle.

Set `background_sync: false` when CI, an init job, or another deployment
component reliably runs `osv sync`:

```yaml
policy:
  osv:
    on_error: "block"
    local:
      sqlite_path: "/var/lib/osv-proxy/osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: "block"
      background_sync: false
      sync_interval: "1h"
```

`/healthz` reports process liveness. `/readyz` verifies that every ecosystem
has a healthy, complete, non-stale generation. Missing or stale data remains
unready and fails closed under the default policy.

Choose `max_staleness` and the external update schedule together. Keep
`on_error: block` and `on_stale: block` unless your deployment has an explicit
fail-open risk decision.
