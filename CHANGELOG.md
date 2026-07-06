# Changelog

All notable changes to `osv-proxy` are tracked here. Release sections are the
source for GitHub release notes.

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
