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
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    source: live
    on_error: "block"
artifacts:
  behavior: redirect
  trusted_origins: []
```

Validate it with:

```sh
cargo run -- config validate --config examples/basic/osv-proxy.yaml
```

The npm registry, PyPI Simple API, Go module proxy, NuGet service index,
RubyGems registry, and OSV API default to their public URLs.
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
    source: live
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
- `osv.source`: `live` or `local`. Defaults to `live`.
- `osv.on_error`: `block` fails closed; `allow` fails open when the OSV check
  fails or a required OSV result is missing.
- `osv.api_url`: optional OSV API base URL override. Omit it to use
  `https://api.osv.dev`. Used only by live checks.

`MAL-*` records are always classified as malicious, independently of CVSS.
Other OSV IDs are classified as vulnerabilities. Malformed recognized CVSS
vectors follow `osv.on_error`; unknown severity types are unscored.

### Live OSV Mode

Live mode is the default and calls the OSV API while handling install requests:

```yaml
policy:
  osv:
    source: live
    api_url: "https://api.osv.dev"
    on_error: block
```

### Local SQLite OSV Mode

Local mode evaluates synchronized SQLite data and makes no OSV network calls
during install request handling:

```yaml
policy:
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    source: local
    on_error: block
    local:
      sqlite_path: "./osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      retain_raw_advisories: false
      background_sync: false
      sync_interval: "6h"
```

- `local.sqlite_path`: SQLite database path for synchronized OSV advisory
  records. Defaults to `osv-malicious.sqlite` for compatibility.
- `local.max_staleness`: maximum age since the last successful sync before the
  local data is stale. Defaults to `24h`.
- `local.on_stale`: `block` fails closed when local data is stale; `allow`
  fails open. Defaults to `block`.
- `local.retain_raw_advisories`: when true, sync stores the full source OSV
  advisory JSON in SQLite. Defaults to false so the local DB keeps only compact
  normalized lookup data plus advisory metadata needed for policy decisions.
- `local.background_sync`: when true, `serve` starts a background sync task.
  The first full sync runs immediately on startup. Successful cycles repeat
  after `sync_interval`; failed ecosystems retry independently with exponential
  backoff starting at 5 seconds and capped at 5 minutes.
- `local.sync_interval`: background sync interval. It must be between `60s` and
  `7d`; defaults to `6h`.

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
