# Review product scope and invariants

This page defines the supported product boundary. Use it to decide whether
`osv-proxy` fits a deployment before you configure individual registries.

## Product purpose

`osv-proxy` is a read-only package-registry security proxy for npm, PyPI,
Cargo, Go modules, NuGet, RubyGems, and Maven Central.

It provides the following controls:

- Registry-native metadata filtering.
- A minimum package-age gate and missing-publication-time policy.
- OSV malicious-package and vulnerability blocking.
- An inclusive CVSS threshold for non-malicious advisories.
- Exact-version OSV and age-gate allowlist bypasses.
- Exact-version and whole-package manual blocklists.
- A second policy check for package-file routes.
- Redirect or streaming-proxy file delivery.
- Local SQLite OSV evaluation with automatic hourly synchronization.
- Bounded caching of complete policy-filtered metadata responses.
- Strict YAML configuration and structured JSON decisions.

## Default security posture

The default configuration blocks missing or uncertain policy inputs:

```yaml
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
      background_sync: true
      sync_interval: "1h"

artifacts:
  behavior: "redirect"
```

At the zero CVSS threshold, matching unscored advisories also block. Set
`block_vulnerabilities: false` if you want malicious-package blocking without
general vulnerability blocking.

## Correctness invariants

The implementation preserves the following invariants:

- Metadata and direct package-file routes use the same policy model.
- Retained download URLs return through `osv-proxy` before file delivery.
- A denied proxy-mode file request does not fetch upstream package bytes.
- Package-file routes never use the metadata cache.
- Local OSV errors and malformed recognized CVSS vectors follow `on_error`.
- Vulnerability checks require a complete active OSV generation.
- A failed sync never replaces the last healthy generation.
- A content-changing sync invalidates older cached metadata through a durable
  ecosystem revision.
- Package-age transitions can expire cached metadata before its maximum time
  to live.
- Raw OSV advisory retention is opt-in.

## Supported deployment boundary

The process implements global request budgets, local health and readiness, and
graceful shutdown. It can listen on a shared interface, but it does not
implement internet-edge controls.

Put shared deployments behind a gateway or reverse proxy that supplies:

- TLS termination.
- Authentication and authorization.
- Client rate limiting.
- Edge access control.

## Unsupported capabilities

The following capabilities are not implemented:

- Authentication or package publishing.
- License policy or broad software-composition scanning.
- Search APIs beyond what supported restore clients require.
- Private registry hosting.
- S3-compatible package-file caching.
- MongoDB-compatible advisory storage.
- A structured audit-log or metrics exporter.

Configuration values that select an unimplemented behavior, such as
`proxy_cache_s3`, fail validation.

## Implementation stack

The Rust implementation uses Axum and Tokio for HTTP serving, Reqwest for
bounded upstream access, Serde for protocol data, Rusqlite for the local OSV
store, `polycvss` for CVSS parsing, and ecosystem-specific version parsers.
Registry and OSV inputs remain injectable so tests can use hermetic local
fixtures.
