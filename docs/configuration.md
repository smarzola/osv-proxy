# Configure osv-proxy

`osv-proxy` reads YAML configuration. Every section has secure defaults, and
unknown keys fail validation. Validate a file before you use it:

```sh
osv-proxy config validate --config /path/to/osv-proxy.yaml
```

## Start with the example

The following configuration shows the default operating posture:

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
      on_stale: "block"
      retain_raw_advisories: false
      background_sync: true
      sync_interval: "1h"

artifacts:
  behavior: "redirect"
  trusted_origins: []
```

Public registry URLs are defaults. Add `upstreams` only when you use a mirror,
test fixture, or private gateway.

## Configure the server

```yaml
server:
  bind: "127.0.0.1:8080"
  public_base_url: "http://127.0.0.1:8080"
```

| Field | Default | Description |
| --- | --- | --- |
| `bind` | `127.0.0.1:8080` | Listener address as numeric IPv4, bracketed IPv6, or an ASCII DNS hostname with a port |
| `public_base_url` | `http://127.0.0.1:8080` | Base URL used in proxy-owned metadata and package-file links |

HTTP URLs must include a host, use HTTP or HTTPS, and omit credentials, a
query, and a fragment. Advertised and outbound URLs cannot use an unspecified
address or port zero. Intentional base paths and private HTTP mirrors remain
valid.

A non-loopback listener produces a startup warning. Put a shared deployment
behind a trusted gateway or reverse proxy that provides TLS, authentication,
client rate limiting, and edge access control.

## Configure request limits

```yaml
limits:
  ingress_requests: 128
  egress_requests: 32
  background_sync_requests: 4
  queue_timeout: "2s"
```

| Field | Default | Description |
| --- | ---: | --- |
| `ingress_requests` | 128 | Maximum active registry and readiness responses, including streamed bodies |
| `egress_requests` | 32 | Maximum aggregate registry and package-file upstream requests |
| `background_sync_requests` | 4 | Separate outbound limit for OSV synchronization |
| `queue_timeout` | `2s` | Maximum wait for an outbound permit |

All values must be greater than zero. An ingress overflow returns HTTP `503`
immediately. An install-path queue timeout returns HTTP `503` with
`Retry-After: 1`. `/healthz` remains outside ingress admission.

A background-sync timeout records a failed attempt and enters the bounded
retry schedule. It does not consume install-path egress capacity.

## Configure the metadata cache

```yaml
metadata_cache:
  enabled: true
  capacity_bytes: 134217728
  max_entry_bytes: 16777216
  ttl: "5m"
  fill_concurrency: 8
```

| Field | Default | Valid values |
| --- | ---: | --- |
| `enabled` | `true` | `true` or `false` |
| `capacity_bytes` | 134217728 | 1 byte through 4 GiB |
| `max_entry_bytes` | 16777216 | 1 byte through 128 MiB and no more than `capacity_bytes` |
| `ttl` | `5m` | Greater than zero and no more than `24h` |
| `fill_concurrency` | 8 | 1 through 1024 |

`capacity_bytes` accounts for keys, response headers, and response bodies. It
does not provide a hard process-memory ceiling.

The cache stores complete successful responses for supported policy-filtered
metadata `GET` routes. It excludes static discovery, health, readiness, and
every package-file route. It also excludes oversized, overloaded,
unsuccessful, and transient policy-error responses.

The key includes the exact path and query, material request headers, and the
ecosystem's committed OSV content revision. A content-changing sync advances
the revision in the same transaction as the advisory change, making older
cache entries unreachable to new requests.

Identical misses share one fill. `fill_concurrency` bounds distinct fills. A
package-age transition can expire an entry before `ttl`.

## Configure registry upstreams

You can override any public registry endpoint:

```yaml
upstreams:
  cargo:
    sparse_index_url: "https://index.crates.io"
    download_url: "https://static.crates.io/crates"
  go:
    proxy_url: "https://proxy.golang.org"
  maven:
    repository_url: "https://repo.maven.apache.org/maven2"
  npm:
    registry_url: "https://registry.npmjs.org"
  nuget:
    service_index_url: "https://api.nuget.org/v3/index.json"
  pypi:
    simple_url: "https://pypi.org/simple"
  rubygems:
    registry_url: "https://rubygems.org"
```

| Field | Purpose |
| --- | --- |
| `cargo.sparse_index_url` | Cargo sparse index |
| `cargo.download_url` | Canonical crates.io package files |
| `go.proxy_url` | Go module proxy |
| `maven.repository_url` | Maven release repository |
| `npm.registry_url` | npm package metadata and canonical tarball discovery |
| `nuget.service_index_url` | NuGet V3 restore service index |
| `pypi.simple_url` | PyPI Simple API |
| `rubygems.registry_url` | RubyGems Compact Index, version metadata, and gems |

Every URL follows the server URL validation rules.

## Configure package-file delivery

```yaml
artifacts:
  behavior: "redirect"
  trusted_origins:
    - "http://packages.internal.example:8081"
```

`behavior` accepts the following values:

| Value | Behavior |
| --- | --- |
| `redirect` | Returns HTTP `302` to the validated upstream file after policy passes |
| `proxy` | Fetches the validated upstream file and streams its response |

`redirect` is the default. `proxy_cache_s3` is reserved and fails validation.

`trusted_origins` contains exact HTTP or HTTPS origins. Each value must omit
credentials, paths, queries, and fragments. Keep this list small because it
applies across ecosystems and can explicitly permit private addresses.

Before a proxy connection, `osv-proxy` validates the URL and every resolved
address. Public HTTPS origins are allowed for registry content-delivery
networks. Plain HTTP and non-public destinations require an exact configured
ecosystem origin or a `trusted_origins` entry. Package-file requests ignore
system HTTP proxy settings and do not follow upstream redirects.

## Configure package policy

```yaml
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    on_error: "block"
```

| Field | Default | Description |
| --- | --- | --- |
| `minimum_age` | `72h` | Minimum time after publication before a version is eligible |
| `missing_publish_time` | `block` | `block` or `allow` when a registry does not provide a publication time |
| `osv.block_malicious` | `true` | Blocks matching OSV `MAL-*` records |
| `osv.block_vulnerabilities` | `true` | Blocks other matching OSV advisories according to the threshold |
| `osv.minimum_cvss_score` | `0` | Inclusive finite threshold from 0 through 10 |
| `osv.on_error` | `block` | `block` or `allow` for checker failures, missing results, or malformed recognized CVSS vectors |

At threshold zero, matching unscored vulnerabilities block. At a positive
threshold, unscored vulnerabilities do not block. `MAL-*` records remain
malicious regardless of CVSS.

See [Understand policy decisions](policy.md) for evaluation order and
allowlist behavior.

## Configure local OSV data

Local SQLite is the only OSV policy source:

```yaml
policy:
  osv:
    local:
      sqlite_path: "./data/osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: "block"
      retain_raw_advisories: false
      background_sync: true
      sync_interval: "1h"
```

| Field | Default | Description |
| --- | --- | --- |
| `sqlite_path` | `osv-malicious.sqlite` | Path to the synchronized SQLite database |
| `max_staleness` | `24h` | Maximum age since the last successful sync; must be greater than zero |
| `on_stale` | `block` | `block` or `allow` after `max_staleness` |
| `retain_raw_advisories` | `false` | Stores full source advisory JSON when `true` |
| `background_sync` | `true` | Starts an immediate background update and later scheduled updates |
| `sync_interval` | `1h` | Delay after a successful cycle; valid from `60s` through `7d` |

The server does not wait for the immediate background update before it starts
serving. A healthy, non-stale database remains usable while it refreshes.
Missing, incomplete, unhealthy, or stale data remains unready and fails closed
by default until synchronization succeeds.

Failed ecosystems retry independently with exponential backoff from five
seconds through five minutes. A fully successful cycle waits for
`sync_interval`.

To update the database explicitly, run:

```sh
osv-proxy osv sync --config /path/to/osv-proxy.yaml
```

The compatibility command `malicious sync` performs the same operation.
Concurrent syncs against one SQLite path fail through a cross-process sidecar
lock.

For deterministic startup, validate and preseed the database before you start
the server:

```sh
mkdir -p /var/lib/osv-proxy
osv-proxy config validate --config /etc/osv-proxy/osv-proxy.yaml
osv-proxy osv sync --config /etc/osv-proxy/osv-proxy.yaml
osv-proxy serve --config /etc/osv-proxy/osv-proxy.yaml
```

See [Manage OSV advisory data](osv-data.md) for transaction, migration, and
readiness semantics.

## Configure an allowlist

Allowlist entries require an exact version:

```yaml
allowlist:
  - ecosystem: npm
    name: "@company/safe-package"
    version: "1.2.3"
    bypass_age_gate: true
    bypass_osv: false
    reason: "Approved emergency release"
```

`bypass_age_gate` and `bypass_osv` are independent. An entry with
`bypass_osv: true` requires a nonempty `reason`. Wildcard allowlist versions
fail validation.

## Configure a blocklist

Blocklist entries accept exact versions or `*`:

```yaml
blocklist:
  - ecosystem: npm
    name: "event-stream"
    versions: ["*"]
    reason: "Blocked after an internal incident"
  - ecosystem: pypi
    name: "example-package"
    versions: ["1.0.0", "1.0.1"]
    reason: "Versions fail internal policy"
```

Version ranges such as `<4.17.21` are not supported and fail validation.
