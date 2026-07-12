# Product Specification

`osv-proxy` is a Rust package-registry security proxy for npm, PyPI,
Cargo/crates.io, Go modules, NuGet restore, RubyGems/Bundler, and Maven Central
for Maven and Gradle.

```text
npm/pnpm/yarn/bun   pip/uv/poetry   Cargo   Go   dotnet/NuGet   Bundler   Maven/Gradle
         \              |            |      |        |           |          /
                          osv-proxy
                              |
          metadata filtering + artifact policy recheck
                              |
 npm / PyPI / crates.io / Go proxy / NuGet / RubyGems / Maven Central
```

## Current Product

The implemented product provides:

- registry-native metadata filtering for all seven supported ecosystems;
- a minimum package-age gate and missing-publish-time policy;
- active OSV `MAL-*` and CVSS-threshold vulnerability blocking;
- exact-version OSV and age-gate allowlist bypasses;
- exact-version and whole-package manual blocklists;
- a second policy check on direct artifact routes;
- HTTP redirect and plain streaming proxy artifact behavior;
- live OSV API evaluation with bounded, deduplicated detail hydration as an
  explicit opt-in;
- generation-scoped local SQLite OSV evaluation with no OSV request on the
  install path;
- strict YAML configuration and structured JSON decisions.

Default security posture:

```yaml
policy:
  minimum_age: "72h"
  missing_publish_time: block
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    source: local
    on_error: block
    local:
      sqlite_path: "./data/osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      background_sync: false
artifacts:
  behavior: redirect
```

The zero threshold intentionally blocks matching unscored advisories. Operators
who need the prior behavior can set `block_vulnerabilities: false` while
retaining malicious-package blocking. Any OSV bypass is exact-version only,
explicit, and requires a reason.

## Invariants

- Metadata and direct artifact delivery evaluate the same current policy.
- Redirected artifact URLs remain owned by `osv-proxy` until the second check.
- A denied proxy-mode artifact is rejected before upstream package bytes are
  fetched.
- Live OSV failures and malformed recognized vectors follow `on_error`.
- Local vulnerability checks require a complete active dataset generation.
- Raw OSV advisory retention is opt-in.

## Implementation

The current implementation uses Axum/Tokio, Reqwest, Serde, Rusqlite,
`polycvss`, and ecosystem-specific version parsers. External OSV and registry
access remains behind injectable interfaces so policy and adapters can be
tested hermetically.

## Future Work

Metadata caching with cachebox, S3-compatible artifact caching,
MongoDB-compatible advisory storage, authentication/publishing controls,
license policy, and a structured audit-log sink are possible future features.
They are not current product capabilities or accepted configuration modes.
