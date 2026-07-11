# Changelog

All notable changes to `osv-proxy` are tracked here. Release sections are the
source for GitHub release notes.

## [Unreleased]

## [0.7.1] - 2026-07-11

### Changed

- Fix tagged release validation so annotated tags do not conflict with a
  redundant tag fetch before tests and binary builds.

## [0.7.0] - 2026-07-11

### Added

- Add Maven Central repository support for Maven and Gradle through `/maven/`,
  with policy-filtered release metadata and Maven-compatible version ordering.
- Protect POMs, JARs, Gradle module metadata, classifiers, signatures, and
  checksums through policy-aware redirect or proxy delivery.
- Add live and local OSV evaluation for canonical Maven coordinates, including
  Maven advisory synchronization and CLI `check`/`eval` identities.
- Add hermetic Maven and Gradle coverage for transitive graphs, BOM imports,
  dynamic versions, Gradle Module Metadata, lock state, and policy denials.

### Changed

- Provision pinned Java 21, Maven 3.9.11, and Gradle 8.14.3 clients in CI and
  tagged release tests.

## [0.6.0] - 2026-07-11

### Added

- Add RubyGems Compact Index support for Bundler, including policy-filtered gem
  metadata, RubyGems-compatible version ordering, and live or local OSV checks.
- Protect `.gem` artifact delivery through policy-aware redirects or proxying.
- Add hermetic Bundler coverage for dependencies, platforms, prereleases, fresh
  installs, and locked-version denials.

### Changed

- Provision Ruby 3.3.8 and Bundler 2.5.23 in CI and tagged release tests.

## [0.5.0] - 2026-07-11

### Added

- Block active OSV vulnerability advisories by default, with CVSS v2, v3, and
  v4 base-score evaluation, package-level severity precedence, and configurable
  `policy.osv.minimum_cvss_score`.
- Add canonical `osv sync` and generation-scoped local storage for all supported
  OSV advisories, with atomic bootstrap/catch-up and indexed exact/range lookup.

### Changed

- The default OSV policy now blocks matching unscored vulnerabilities at the
  default zero threshold. Set `policy.osv.block_vulnerabilities: false` to keep
  malicious-only behavior.
- Full local OSV storage is materially larger than the former `MAL-*`-only
  dataset; raw advisory JSON remains opt-in.

## [0.4.1] - 2026-07-09

### Changed

- Updated the hermetic .NET restore tests to explicitly permit their
  loopback-only HTTP NuGet source under the SDK's HTTPS-source enforcement.

## [0.4.0] - 2026-07-09

### Added

- Added Cargo and crates.io sparse-index support with policy-filtered version
  discovery and protected crate downloads.
- Added Go module proxy support for version discovery, metadata, module files,
  and zip downloads without requiring Git.
- Added restore-scoped NuGet V3 support for service discovery, registrations,
  flat-container metadata, packages, and nuspecs.
- Added live and local OSV evaluation for crates.io, Go, and NuGet, including
  ecosystem-specific version range handling.
- Added hermetic real-client coverage for Cargo, Go, and .NET restore in both
  redirect and streaming proxy modes, including fresh and locked denials.

## [0.3.1] - 2026-07-08

### Changed

- Local malicious SQLite sync no longer stores full raw OSV advisory JSON by
  default, substantially reducing new local database size.
- Added `policy.osv.local.retain_raw_advisories` for operators who need raw OSV
  advisory JSON retained for audit or debugging.

## [0.3.0] - 2026-07-08

### Added

- Added local SQLite malicious-package mode with `policy.osv.source: local`.
- Added `osv-proxy malicious sync --config <path>` to bootstrap and
  incrementally update npm and PyPI `MAL-*` records from OSV GCS dumps.
- Added server-managed background malicious-data sync for local mode.
- Added local evaluation for OSV exact affected versions and npm/PyPI range
  events without OSV network calls during install request handling.

### Changed

- Documented local SQLite malicious storage, sync operations, staleness
  behavior, and fail-closed defaults.
- Clarified that MongoDB-compatible and mongolino storage remain possible
  future backends rather than the active local store.

## [0.2.1] - 2026-07-06

### Changed

- Clarified README and repository positioning around OSV data plus local policy.
- Switched the crate to the Rust 2024 edition.

### Added

- Added Apache-2.0 licensing for `osv-proxy`.
- Documented that cached, exported, or redistributed advisory data keeps its
  original source licensing and attribution requirements.

## [0.2.0] - 2026-07-06

### Added

- Plain artifact proxy mode with `artifacts.behavior: proxy` for npm tarballs
  and PyPI files.
- Configurable artifact delivery behavior while keeping redirect mode as the
  default.
- Proxy-mode tests covering streamed upstream bytes, forwarded artifact headers,
  blocked-artifact short-circuiting, and upstream artifact error handling.

### Changed

- Documented artifact delivery modes in the README, configuration reference,
  registry behavior guide, and milestone plan.

## [0.1.0] - 2026-07-06

### Added

- Initial `osv-proxy` binary with npm and PyPI policy-proxy support.
- YAML configuration loading and validation.
- `serve`, `check`, `eval`, and `config validate` commands.
- Minimum-age, manual allowlist, manual blocklist, missing-publish-time, and
  OSV `MAL-*` malicious-package policy checks.
- npm metadata filtering and tarball redirect policy enforcement.
- PyPI Simple HTML/JSON filtering and file redirect policy enforcement.
- GitHub release automation for Linux and macOS binaries on x64 and arm64.
