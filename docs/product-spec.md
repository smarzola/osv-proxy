# Product Specification

`osv-proxy` is a policy-enforcing package registry proxy for npm, PyPI,
Cargo/crates.io, Go modules, and NuGet restore.

```text
npm / pnpm / yarn / bun / pip / uv / poetry
        |
        v
    osv-proxy
        |
        +-- policy engine
        +-- OSV malicious and vulnerability checks
        +-- minimum age gate
        +-- exact-version allowlist
        +-- optional metadata cache via cachebox
        +-- optional artifact proxy/cache
        |
        v
npm registry / PyPI / files.pythonhosted.org
```

## Product Summary

`osv-proxy` protects dependency installation by:

- filtering package metadata before clients see versions or files
- enforcing a configurable minimum age gate
- blocking known malicious packages and active vulnerabilities from OSV
- supporting exact-version allowlist overrides
- supporting manual package and version blocklists
- optionally proxying or caching package artifacts
- supporting cheap public-service redirect mode to avoid large artifact egress costs

## Name

- Product name: `osv-proxy`
- Main binary: `osv-proxy`

## Implementation Language

Use Rust.

Recommended stack:

- `axum` for HTTP server
- `tokio` for async runtime
- `reqwest` for HTTP client
- `serde`, `serde_json`, and `serde_yaml` for serialization and config
- `tracing` for structured logs
- `tower` for middleware
- `chrono` for time handling
- `rusqlite` for local OSV advisory storage
- `object_store` or `aws-sdk-s3` for S3-compatible artifact cache
- `semver` for npm version helpers
- `pep440_rs` for PyPI version helpers, if useful

Keep external systems behind traits so the core policy engine stays easy to test.

## Default Security Posture

Defaults should be conservative:

```yaml
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  osv:
    block_malicious: true
    on_error: "block"
```

Developer mode can be more permissive, but must be explicit.

## Important Invariants

- Policy is checked during metadata generation.
- Policy is checked again during artifact serving.
- Cached metadata never bypasses current policy.
- Cached artifacts never bypass current policy.
- Allowlist bypasses are exact-version only.
- Malicious bypass requires explicit config and a reason.
- Live OSV mode may call OSV during request handling.
- Local OSV mode must not call OSV during install-request handling.
- Metadata cache is either disabled or cachebox-backed.
- There is no memory metadata cache.
- Redirect mode rewrites artifact URLs to `osv-proxy` URLs, not upstream URLs.

## Final Product Definition

`osv-proxy` is a Rust registry security proxy for npm and PyPI.

It provides:

- minimum age gate for newly published packages
- built-in OSV malicious and CVSS-threshold vulnerability blocking
- exact-version allowlist escape hatches
- manual blocklist
- metadata filtering
- artifact redirect, proxy, and S3-cache modes
- live OSV API mode
- local SQLite all-advisory store mode
- possible future MongoDB-compatible malicious storage
- cachebox support for metadata caching
- YAML configuration
- structured audit logs
- cheap public deployment mode with low artifact egress
