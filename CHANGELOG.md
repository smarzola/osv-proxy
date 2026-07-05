# Changelog

All notable changes to `osv-proxy` are tracked here. Release sections are the
source for GitHub release notes.

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
