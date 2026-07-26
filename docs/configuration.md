# Configuration

`osv-proxy` uses YAML configuration. Unknown keys fail validation so policy
typos do not silently change install behavior.

Cargo defaults to `https://index.crates.io` for `upstreams.cargo.sparse_index_url`
and `https://static.crates.io/crates` for `upstreams.cargo.download_url`.
Optional sparse-record `pubtime` uses the existing age policy; missing values
follow `policy.missing_publish_time`.

## Example

```yaml
server:
  bind: "127.0.0.1:8080"
  public_base_url: "http://127.0.0.1:8080"
limits:
  ingress_requests: 128
  egress_requests: 32
  background_sync_requests: 4
  queue_timeout: "2s"
metadata_cache:
  enabled: true
  capacity_bytes: 134217728
  max_entry_bytes: 16777216
  ttl: "5m"
  fill_concurrency: 8
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    on_error: "block"
    local:
      sqlite_path: "./data/osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      retain_raw_advisories: false
      background_sync: true
      sync_interval: "1h"
artifacts:
  behavior: redirect
  trusted_origins: []
```

Validate it with:

```sh
cargo run -- config validate --config examples/basic/osv-proxy.yaml
```

The npm registry, PyPI Simple API, Go module proxy, NuGet service index, and
RubyGems registry default to their public URLs.
Maven defaults to Maven Central at `https://repo.maven.apache.org/maven2`.
Configure them only when routing through a mirror, fixture, or private gateway.

## Server

```yaml
server:
  bind: "127.0.0.1:8080"
  public_base_url: "http://127.0.0.1:8080"
```

- `bind`: local socket address for the HTTP server.
- `public_base_url`: URL used when advertising or rewriting proxy-owned package
  metadata and artifact links.

`bind` accepts numeric IPv4, bracketed IPv6, or an ASCII DNS hostname plus a
port. `public_base_url` and every upstream URL must use
HTTP or HTTPS, include a host, and contain no credentials, query, or fragment.
Advertised and outbound URLs reject unspecified addresses (`0.0.0.0` and
`[::]`) and explicit port zero because clients cannot use those destinations.
Private HTTP mirrors, loopback fixtures on nonzero ports, and intentional base
paths remain supported.

A resolved non-loopback bind emits a startup warning. For shared deployments,
put `osv-proxy` behind a trusted gateway or reverse proxy that provides TLS,
authentication, client rate limiting, and edge access control. Those controls
are intentionally not implemented in `osv-proxy`.

## Runtime Limits

```yaml
limits:
  ingress_requests: 128
  egress_requests: 32
  background_sync_requests: 4
  queue_timeout: "2s"
```

- `ingress_requests`: maximum active registry and readiness responses,
  including streamed artifact bodies. Excess requests receive HTTP 503
  immediately. Dependency-free `/healthz` remains outside admission so a
  saturated process can still report liveness.
- `egress_requests`: aggregate install-path outbound request limit shared by
  registry metadata and artifact delivery. Permits are retained
  until buffered or streamed response bodies finish.
- `background_sync_requests`: separate outbound limit for OSV dump sync, so
  synchronization cannot consume install-path egress capacity.
- `queue_timeout`: maximum wait for either egress lane. Install-path expiry
  returns HTTP 503 with `Retry-After: 1`, even when an adapter or fail-open
  policy would otherwise translate the underlying error. Background-sync
  expiry records a failed sync attempt and follows the existing bounded retry
  schedule; it has no client HTTP response.

All limits must be greater than zero. Existing adapter-local fan-out caps remain
in effect inside the aggregate process budget.

## Metadata Cache

```yaml
metadata_cache:
  enabled: true
  capacity_bytes: 134217728
  max_entry_bytes: 16777216
  ttl: "5m"
  fill_concurrency: 8
```

- `enabled`: enables the process-local cache. Defaults to true.
- `capacity_bytes`: weighted capacity across keys, headers, and response
  bodies. Defaults to 128 MiB, accepts 1 byte through 4 GiB, and is not a hard
  process-RSS limit.
- `max_entry_bytes`: maximum response body retained. Defaults to 16 MiB and
  accepts 1 byte through 128 MiB; it must not exceed `capacity_bytes`.
- `ttl`: maximum entry lifetime. Defaults to `5m`; a package-age transition
  can expire an entry sooner. It must be greater than zero and at most `24h`.
- `fill_concurrency`: maximum distinct complete metadata fills running at
  once. Identical misses share one fill. Defaults to 8 and accepts 1 through
  1024.

Only supported policy-filtered metadata GET routes are admitted. Static
discovery/configuration responses and direct artifact routes are excluded.
The key includes the exact path/query, ecosystem OSV content revision, and
material request headers. Content-changing sync commits advance that revision,
so old policy output cannot be returned after the commit. Transient policy or
revision failures still use bounded singleflight but are not retained.

The admitted route classes are npm package metadata, PyPI project pages, Cargo
sparse records, Go list/latest/info responses, NuGet registration and
flat-container version indexes, RubyGems compact info, and Maven metadata
(including its checksum forms).

## Upstreams

```yaml
upstreams:
  npm:
    registry_url: "https://registry.npmjs.org"
  pypi:
    simple_url: "https://pypi.org/simple"
  go:
    proxy_url: "https://proxy.golang.org"
  nuget:
    service_index_url: "https://api.nuget.org/v3/index.json"
  rubygems:
    registry_url: "https://rubygems.org"
  maven:
    repository_url: "https://repo.maven.apache.org/maven2"
```

- `npm.registry_url`: upstream npm registry metadata endpoint.
- `pypi.simple_url`: upstream PyPI Simple API endpoint. Project pages are
  fetched as Simple JSON for policy evaluation.
- `go.proxy_url`: upstream Go module proxy endpoint.
- `nuget.service_index_url`: upstream NuGet V3 restore service index.
- `rubygems.registry_url`: upstream RubyGems registry root used for Compact
  Index metadata, version metadata, and canonical gem downloads.
- `maven.repository_url`: upstream Maven repository root used for release
  metadata, POMs, JARs, Gradle module metadata, classifiers, signatures, and
  checksums.

All upstream values have public registry defaults, so most
local configs can omit this section.

## Artifacts

```yaml
artifacts:
  behavior: redirect
  trusted_origins:
    - "http://packages.internal.example:8081"
```

- `behavior`: `redirect` or `proxy`. Defaults to `redirect`.
- `trusted_origins`: exact HTTP or HTTPS origins that artifact delivery may
  contact in addition to the configured ecosystem upstreams. Entries must not
  contain credentials, paths, queries, or fragments. Keep this list minimal;
  it is shared by all ecosystems and may explicitly permit private addresses.
- `redirect`: after the second policy check, allowed artifact requests return
  `302 Location` to the upstream tarball or file URL.
- `proxy`: after the second policy check, allowed artifact requests fetch the
  verified upstream artifact URL and stream the upstream response through
  `osv-proxy`.

Artifact destinations are restricted before any proxy connection. Public HTTPS
origins are allowed so registries can use their public CDNs. Plain HTTP and
private, loopback, link-local, or otherwise non-public addresses require an
exact origin configured for that ecosystem under `upstreams` or listed in
`trusted_origins`. Artifact requests do not use system HTTP proxies, and
upstream redirects are rejected instead of followed. NuGet registration URLs
discovered through service-index and page metadata use the same boundary.

`proxy_cache_s3` is reserved for future S3-compatible artifact caching and is
rejected as unsupported.

## Policy

```yaml
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  osv:
    block_malicious: true
    on_error: "block"
```

- `minimum_age`: minimum age before a package version can be installed. It must
  be a valid duration that fits policy evaluation.
- `missing_publish_time`: `block` or `allow`.
- `osv.block_malicious`: when true, OSV `MAL-*` records block package versions.
  Defaults to true.
- `osv.block_vulnerabilities`: when true, other active matching OSV advisories
  block according to `minimum_cvss_score`. Defaults to true. Set false for the
  malicious-only compatibility behavior.
- `osv.minimum_cvss_score`: inclusive threshold from 0 through 10. A scored
  advisory blocks when its highest applicable base score is greater than or
  equal to this value. At the default zero, matching advisories without a score
  also block; at a positive threshold they do not.
- `osv.on_error`: `block` fails closed; `allow` fails open when the OSV check
  fails or a required OSV result is missing.

`MAL-*` records are always classified as malicious, independently of CVSS.
Other OSV IDs are classified as vulnerabilities. Malformed recognized CVSS
vectors follow `osv.on_error`; unknown severity types are unscored.

### Local SQLite OSV Data

OSV policy evaluates synchronized SQLite data and makes no OSV network calls
during install request handling:

```yaml
policy:
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    on_error: block
    local:
      sqlite_path: "./osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      retain_raw_advisories: false
      background_sync: true
      sync_interval: "1h"
```

Local SQLite is the only OSV policy source. Remote request-path queries are not
supported, and unknown keys are rejected.

- `local.sqlite_path`: SQLite database path for synchronized OSV advisory
  records. Defaults to `osv-malicious.sqlite` for compatibility.
- `local.max_staleness`: maximum age since the last successful sync before the
  local data is stale. Defaults to `24h`.
- `local.on_stale`: `block` fails closed when local data is stale; `allow`
  fails open. Defaults to `block`.
- `local.retain_raw_advisories`: when true, sync stores the full source OSV
  advisory JSON in SQLite. Defaults to false so the local DB keeps only compact
  normalized lookup data plus advisory metadata needed for policy decisions.
- `local.background_sync`: when true, `serve` starts a background sync task and
  runs an immediate update without waiting for it before serving. A complete
  database is updated incrementally; missing or incomplete data is bootstrapped
  from the full OSV archive. Successful cycles repeat after `sync_interval`;
  failed ecosystems retry independently with exponential backoff starting at 5
  seconds and capped at 5 minutes. Defaults to true.
- `local.sync_interval`: background sync interval. It must be between `60s` and
  `7d`; defaults to `1h`.

Populate or refresh the SQLite database explicitly with:

```sh
osv-proxy osv sync --config /path/to/osv-proxy.yaml
```

The sync command downloads npm, PyPI, Go, crates.io, NuGet, RubyGems, and Maven OSV GCS dumps,
attempts each ecosystem independently, stores successful advisory generations,
and reports per-ecosystem successes and failures. Concurrent sync commands for
the same SQLite store are rejected across processes through an advisory lock on
the adjacent `<sqlite_path>.sync.lock` file.
`malicious sync` is a compatibility alias. Full advisory storage is materially
larger than the former malicious-only database. Missing, corrupt,
unhealthy, or stale local data fails closed by default through `on_error:
block` and `local.on_stale: block`.

For startup-sensitive deployments, preseed the database before launching the
proxy:

```sh
mkdir -p /var/lib/osv-proxy
osv-proxy config validate --config /etc/osv-proxy/osv-proxy.yaml
osv-proxy osv sync --config /etc/osv-proxy/osv-proxy.yaml
osv-proxy serve --config /etc/osv-proxy/osv-proxy.yaml
```

The sync command should run in a CI job, image-build step, init job, or other
deployment step that owns the database before the serving process starts. For
an image-based deployment, bake the completed SQLite file into the image or
mount it from a prepared persistent volume. A complete, non-stale database is
ready immediately. With `background_sync: true`, it remains usable while an
incremental refresh runs; with the default `on_stale: block`, missing or stale
data remains unready and fail-closed until synchronization succeeds. See
[performance and fast boot](performance.md) for measured startup, request-path,
and synchronization costs.

## Allowlist

Allowlist entries are exact-version only.

```yaml
allowlist:
  - ecosystem: npm
    name: "@company/safe-package"
    version: "1.2.3"
    bypass_age_gate: true
    bypass_osv: false
    reason: "Internal emergency release"
```

`bypass_osv: true` requires a non-empty `reason`.

## Blocklist

Blocklist entries support exact versions and `*`.

```yaml
blocklist:
  - ecosystem: npm
    name: "event-stream"
    versions: ["*"]
    reason: "Manually blocked"
```

Version ranges such as `<4.17.21` are not supported.
