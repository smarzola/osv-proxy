# Repository Instructions

- Keep the product centered on deterministic package policy enforcement, not broad security scanning.
- Keep npm and PyPI specifics inside ecosystem adapter documentation and adapter modules. The core policy model should stay ecosystem-neutral.
- Do not add an in-process metadata cache. Metadata caching is either disabled or cachebox-backed.
- Preserve the core invariant: policy is checked during metadata generation and checked again during artifact serving.

## Releases

- Release tags must be plain semver tags on `main`: `vMAJOR.MINOR.PATCH`.
- Before tagging, update `Cargo.toml` to the release version and add a dated `## [MAJOR.MINOR.PATCH] - YYYY-MM-DD` section to `CHANGELOG.md`.
- Keep each release's changelog section agent-written and user-facing. That exact section becomes the GitHub release notes.
- Run `cargo fmt --check` and `cargo test` before cutting the tag.
- Cut releases from an up-to-date `main` by pushing the commit, then pushing the tag:
  `git tag vMAJOR.MINOR.PATCH && git push origin main vMAJOR.MINOR.PATCH`.
- The release workflow builds four archives: Linux x64, Linux arm64, macOS Intel, and macOS arm64. It publishes them with `SHA256SUMS` to the GitHub release.
