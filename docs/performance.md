# Performance and Fast Boot

`osv-proxy` uses local SQLite OSV evaluation so the install path is bounded by
the local process and registry upstream. OSV network access occurs during
explicit or background synchronization, not package requests.

This page records representative measurements and the operational choices that
matter most for startup and request latency.

## Baseline

Measurements below were captured on 2026-07-12 on a macOS arm64 development
machine. Registry timings are observations, not service-level guarantees;
public upstream load and cache state will move them around.

The local-vs-policy-off measurements use the same proxy routes and registry
upstreams. `policy-off` disables both OSV checks; `local` uses the synchronized
SQLite store. Response sizes can differ because local OSV filtering removes
blocked versions, so the latency delta is the useful comparison.

| Ecosystem and route | Policy off p50 | Local OSV p50 | Added local path |
| --- | ---: | ---: | ---: |
| npm lodash | 19.1 ms | 21.5 ms | 2.4 ms |
| npm React | 124.5 ms | 128.1 ms | 3.6 ms |
| PyPI urllib3 | 8.4 ms | 9.2 ms | 0.8 ms |
| PyPI Django | 22.4 ms | 60.8 ms | 38.4 ms |
| Go `github.com/pkg/errors` | 12.5 ms | 15.3 ms | 2.8 ms |
| Go `github.com/gin-gonic/gin` | 19.4 ms | 26.3 ms | 6.9 ms |
| Cargo serde | 10.3 ms | 11.0 ms | 0.7 ms |
| Cargo tokio | 17.0 ms | 21.1 ms | 4.1 ms |
| NuGet Newtonsoft.Json | 135.2 ms | 269.1 ms | 133.9 ms |
| NuGet logging abstractions | 136.6 ms | 156.0 ms | 19.4 ms |
| RubyGems rack | 9.1 ms | 30.7 ms | 21.6 ms |
| RubyGems nokogiri | 25.3 ms | 66.2 ms | 40.9 ms |
| Maven commons-lang3 | 62.9 ms | 91.6 ms | 28.7 ms |

The local overhead depends on the size of the upstream metadata response and
the number of versions that must be evaluated. Small metadata documents add
only a few milliseconds; high-cardinality responses require more parsing and
policy evaluation work.

### Filtered metadata cache

The table above predates the in-process metadata cache and describes cold
route work. Supported metadata GET routes now retain the complete filtered
HTTP representation. A hit skips the upstream fetch, parsing, SQLite policy
checks, filtering, and serialization. No cache-hit latency or throughput
number is claimed here until the benchmark matrix is rerun.

Cache lookup and LRU maintenance are O(1). The default weighted capacity is
128 MiB, maximum body size is 16 MiB, TTL is five minutes, and at most eight
distinct fills run concurrently. This accounting does not include every
allocator/runtime overhead and therefore is not a process-RSS ceiling.

### Process and sync footprint

These measurements also predate the in-process metadata cache. They remain
cold-path and synchronization reference points, not current steady-state cache
footprint measurements.

| Measurement | Result |
| --- | ---: |
| Release binary | 9.886 MiB |
| Release archive | 4.319 MiB |
| `/healthz` sequential p50 | 0.147 ms |
| `/healthz`, 128 persistent connections | 124k requests/sec, 0 errors |
| Fresh idle RSS | 9.0 MiB |
| RSS after health load | 13.7 MiB |
| RSS after a large React metadata response | 81.6 MiB |
| Fresh all-ecosystem OSV sync | 21.37 s |
| Fresh sync peak RSS | 220.6 MiB |
| Full synchronized SQLite database | 194.85 MiB |

The health load used persistent HTTP/1.1 connections, so it is a server smoke
measurement rather than a capacity limit. Large metadata responses naturally
increase transient RSS because the proxy must parse and filter the document.

## Fast boot with a preseeded database

Prepare the database before launch and mount or ship the completed file with
the service when startup should be independent of the OSV network. A valid,
non-stale database can serve immediately while an optional background update
runs.

A simple deployment sequence is:

```sh
mkdir -p /var/lib/osv-proxy

# Run this in CI, an image-build job, or a deployment/init job.
osv-proxy config validate --config /etc/osv-proxy/osv-proxy.yaml
osv-proxy osv sync --config /etc/osv-proxy/osv-proxy.yaml

# Only start the serving process after the preseed step succeeds.
exec osv-proxy serve --config /etc/osv-proxy/osv-proxy.yaml
```

Use a config that points at the prepared file and leaves background sync off
for deterministic startup:

```yaml
policy:
  osv:
    block_malicious: true
    block_vulnerabilities: true
    on_error: block
    local:
      sqlite_path: "/var/lib/osv-proxy/osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      background_sync: false
      sync_interval: "1h"
```

Recommended preseed patterns:

- Bake the completed SQLite file into a release image when the image is
  rebuilt on a controlled schedule.
- Run `osv sync` in a deployment/init job and place the database on a prepared
  persistent volume before starting the proxy.
- In CI, sync and validate the database once, then publish the binary, config,
  and database as one deployment artifact.

`/healthz` only reports process liveness. `/readyz` verifies
that every supported ecosystem has a healthy, complete, non-stale active
generation. With the default `on_stale: block`, missing, incomplete, unhealthy,
or stale data makes readiness false and keeps policy checks fail-closed.

`background_sync: false` performs no automatic OSV sync at boot. It is the
lowest-contention option when a complete, fresh database is prepared by CI or
deployment infrastructure. With `background_sync: true`, the server still
binds and serves immediately while an update starts in the background. A valid
non-stale database remains usable and ready during that update; a missing or
stale database remains unready until synchronization succeeds. A complete
database is refreshed incrementally, while missing or incomplete data requires
a full bootstrap.

After a successful background cycle, the next cycle waits for `sync_interval`.
If only some ecosystems fail, those ecosystems retry independently with bounded
backoff while successful ecosystems retain their active data.

Do not copy an SQLite file while another process is actively writing it. Run
the sync to completion, close the sync process, and then ship the resulting
database. The normal WAL/generation implementation already lets clients read
the last good snapshot while a sync transaction is in progress.

## Choosing synchronization ownership

The default serving process starts an immediate background sync and repeats
successful cycles hourly. Keep that default when the process should own data
freshness. Set `background_sync: false` only when CI, an init job, or another
deployment component reliably runs `osv sync`.

Keep `on_error: block` unless the deployment has an explicit fail-open risk
decision. Configure `max_staleness` and the update schedule to match the
deployment's freshness requirements. Content-changing syncs atomically advance
the cache revision; no-op or failed syncs do not.
