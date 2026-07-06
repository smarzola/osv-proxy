# Repository Instructions

## Releases

- CI runs formatting and tests on every push to `main` and on pull requests.
- Release from an up-to-date `main` using plain semver tags: `vMAJOR.MINOR.PATCH`.
- Before tagging, update `Cargo.toml` and add a dated changelog section for the release.
- Keep release notes user-facing; use the changelog section as the GitHub release notes.
- Run `cargo fmt --check` and `cargo test` before tagging, and report any checks that were skipped.
- The release workflow also reruns formatting and tests on the tagged commit before building binaries.
- Push the release commit and tag together.
