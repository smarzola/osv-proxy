# Performance and Fast Boot

`osv-proxy` defaults to local SQLite OSV evaluation because the install path is
then bounded by the local process and registry upstream, rather than by a
remote OSV query and advisory-detail fan-out. Live mode remains available as an
explicit opt-in when remote freshness is preferred over predictable latency.

This page records representative measurements and the operational choices that
matter most for startup and request latency.

## Baseline

Measurements below were captured on 2026-07-12 on a macOS arm64 development
machine. Registry and OSV network timings are observations, not service-level
guarantees; public upstream load and cache state will move them around.

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

### Live mode

Live OSV is dominated by the remote API rather than local computation. The
client respects the OSV API's 1,000-query `/v1/querybatch` limit, splits larger
requests into bounded concurrent chunks, and hydrates advisory details with
bounded concurrency. Representative requests produced:

- React: HTTP 200, 2,808 versions preserved, 4.77 s.
- TypeScript: HTTP 200, 3,763 versions preserved, 4.10 s.

For packages below the limit, observed OSV batch time was roughly 1.4–4.8 s;
advisory-detail hydration added roughly 0.2–0.36 s for the representative
packages. Live mode has no metadata or detail cache yet.

### Process and sync footprint

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
    source: local
    block_malicious: true
    block_vulnerabilities: true
    on_error: block
    local:
      sqlite_path: "/var/lib/osv-proxy/osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      background_sync: false
      sync_interval: "6h"
```

Recommended preseed patterns:

- Bake the completed SQLite file into a release image when the image is
  rebuilt on a controlled schedule.
- Run `osv sync` in a deployment/init job and place the database on a prepared
  persistent volume before starting the proxy.
- In CI, sync and validate the database once, then publish the binary, config,
  and database as one deployment artifact.

`/healthz` only reports process liveness. For local mode, `/readyz` verifies
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

## Choosing the source

Use the default local source when you need predictable request latency,
network-independent policy enforcement, or fast repeated installs:

```yaml
policy:
  osv:
    source: local
```

Opt into live mode when remote OSV freshness is more important than latency and
the deployment can tolerate multi-second metadata checks:

```yaml
policy:
  osv:
    source: live
    api_url: "https://api.osv.dev"
```

For either source, keep `on_error: block` unless the deployment has an explicit
fail-open risk decision. Local mode still requires regular synchronization;
configure `max_staleness` and an update schedule that match the deployment's
freshness requirements.
