# Configuration

`osv-proxy` uses YAML configuration. Unknown keys fail validation so policy
typos do not silently change install behavior.

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
    source: live
    on_error: "block"
artifacts:
  behavior: redirect
```

Validate it with:

```sh
cargo run -- config validate --config examples/basic/osv-proxy.yaml
```

The npm registry, PyPI Simple API, and OSV API default to their public URLs.
Configure them only when routing through a mirror, fixture, or private gateway.

## Server

```yaml
server:
  bind: "127.0.0.1:8080"
  public_base_url: "http://127.0.0.1:8080"
```

- `bind`: local socket address for the HTTP server.
- `public_base_url`: URL used when rewriting npm tarballs and PyPI file links
  back through `osv-proxy`.

## Upstreams

```yaml
upstreams:
  npm:
    registry_url: "https://registry.npmjs.org"
  pypi:
    simple_url: "https://pypi.org/simple"
```

- `npm.registry_url`: upstream npm registry metadata endpoint.
- `pypi.simple_url`: upstream PyPI Simple API endpoint. Project pages are
  fetched as Simple JSON for policy evaluation.

Both upstream values have the public registry defaults shown above, so most
local configs can omit this section.

## Artifacts

```yaml
artifacts:
  behavior: redirect
```

- `behavior`: `redirect` or `proxy`. Defaults to `redirect`.
- `redirect`: after the second policy check, allowed artifact requests return
  `302 Location` to the upstream tarball or file URL.
- `proxy`: after the second policy check, allowed artifact requests fetch the
  verified upstream artifact URL and stream the upstream response through
  `osv-proxy`.

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
- `osv.source`: `live` or `local`. Defaults to `live`.
- `osv.on_error`: `block` fails closed; `allow` fails open when the OSV check
  fails or a required OSV result is missing.
- `osv.api_url`: optional OSV API base URL override. Omit it to use
  `https://api.osv.dev`. Used only by live checks.

Only OSV records with IDs starting with `MAL-` block package versions. CVEs,
GHSAs, and other advisory records are not package-malicious decisions in
`osv-proxy`.

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

- `local.sqlite_path`: SQLite database path for synchronized OSV malicious
  records. Defaults to `osv-malicious.sqlite`.
- `local.max_staleness`: maximum age since the last successful sync before the
  local data is stale. Defaults to `24h`.
- `local.on_stale`: `block` fails closed when local data is stale; `allow`
  fails open. Defaults to `block`.
- `local.retain_raw_advisories`: when true, sync stores the full source OSV
  advisory JSON in SQLite. Defaults to false so the local DB keeps only compact
  normalized lookup data plus advisory metadata needed for policy decisions.
- `local.background_sync`: when true, `serve` starts a background sync task.
  The first sync runs immediately on startup, then repeats after
  `sync_interval`.
- `local.sync_interval`: background sync interval. It must be between `60s` and
  `7d`; defaults to `6h`.

Populate or refresh the SQLite database explicitly with:

```sh
osv-proxy malicious sync --config /path/to/osv-proxy.yaml
```

The sync command downloads npm and PyPI OSV GCS dumps, stores `MAL-*`
advisories locally, and updates sync health state. Missing, corrupt,
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
