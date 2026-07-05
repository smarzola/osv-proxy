# Goal: Phase-One E2E Hardening and Scope Audit

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Validate and harden the first implemented version of `osv-proxy` end to end. The final product for this phase must run as a Rust HTTP proxy supporting naive OSV mode and redirect artifact behavior only, with no storage and no metadata cache.

This worker should act adversarially: find inconsistencies, unsupported configuration leakage, missing second policy checks, weak tests, and client-breaking response problems.

## Repository Rules

- Do not add local malicious storage, MongoDB, cachebox, proxy streaming, S3, or in-process metadata cache.
- Preserve the invariant that policy is checked during metadata generation and checked again during artifact serving.
- Keep npm and PyPI specifics in their adapters.
- Do not revert changes made by other workers. You are not alone in this codebase.

## Target State

- A supported example config exists for phase one.
- Full test suite passes.
- The server can be smoke-tested against local mocked upstreams.
- Unsupported modes are rejected clearly.
- Documentation accurately describes implementation status without claiming deferred features are implemented.

## Current State

This worker should run after the core, npm, and PyPI implementation workers. If implementation files are missing, stop and report the missing prerequisite.

## Definition of Done

1. `cargo test` passes.
2. `cargo run -- config validate --config <phase-one-example>` succeeds.
3. Unsupported storage/cache/artifact modes fail validation.
4. Tests prove metadata filtering and artifact serving both check policy.
5. README or docs no longer say the repository is documentation-only.
6. Deferred features remain documented as future work, not implemented behavior.

## Milestone Checklist

- [x] Phase-one example config and docs update
- [x] E2E route tests or smoke harness
- [x] Unsupported-mode validation tests
- [x] Final scope audit

Status note, 2026-07-05: Updated README phase-one implementation status, confirmed `examples/phase1/osv-proxy.yaml`, added route-level npm/PyPI e2e tests for metadata/Simple filtering followed by allowed redirects and blocked direct artifact 403s, added explicit `artifacts.behavior: proxy_cache_s3` validation coverage, corrected the PyPI goal commit note to `1c6992c`, and completed the phase-one scope audit. Verification commands run: `cargo fmt`; `cargo test e2e`; `cargo test config`; `cargo run -- config validate --config examples/phase1/osv-proxy.yaml`; `cargo test`; `cargo fmt --check`; `git diff --check`; `rg -n "mongodb|cachebox|S3|proxy_cache_s3|memory cache|HashMap.*cache|artifact cache" src examples docs`; `rg -n "mongodb|cachebox|S3|proxy_cache_s3|memory cache|HashMap.*cache|artifact cache|proxy streaming" src`; `rg -n "PolicyEngine::new\\(config\\)\\.evaluate|evaluate\\(&artifact" src/npm.rs src/pypi.rs src/server.rs`. Commit: 57af350.

## Checkpoint Protocol

When a milestone is complete:

1. Run the milestone's verification commands.
2. Update this file by changing the milestone checkbox from `[ ]` to `[x]`.
3. Add a short status note with the date, exact commands run, and commit hash if available.
4. Commit the code, tests, docs, and status-note update with a focused commit message if committing is available in your workspace.
5. Report the commit hash or state that commits are unavailable before starting the next milestone.

## Milestone 1: Phase-One Example Config and Docs Update

Problem: existing docs describe full v1, but the current implementation is a narrower phase.

Desired behavior: users can find a minimal supported config and understand what is implemented.

Acceptance criteria:

- Add an example config under `examples/phase1/osv-proxy.yaml`.
- README implementation status says phase-one implementation exists.
- README or docs list current support: naive OSV, npm, PyPI, redirect artifacts, no cache, no storage.
- Avoid copying personal Codex instructions into repo docs.

Verification:

```sh
cargo run -- config validate --config examples/phase1/osv-proxy.yaml
```

## Milestone 2: E2E Route Tests or Smoke Harness

Problem: unit tests can miss route integration problems.

Desired behavior: local tests exercise server routes through HTTP-level calls with mocked upstream metadata.

Acceptance criteria:

- Cover npm metadata filtering to tarball redirect.
- Cover PyPI Simple filtering to file redirect.
- Cover blocked artifact returning 403 after metadata route has already been used.
- Do not call live npm, PyPI, or OSV services.

Verification:

```sh
cargo test e2e
```

## Milestone 3: Unsupported-Mode Validation Tests

Problem: phase-one config should not expose settings that imply unimplemented systems.

Desired behavior: unsupported settings fail clearly.

Acceptance criteria:

- `policy.malicious.mode: local` is rejected.
- `metadata_cache.enabled: true` is rejected.
- `artifacts.behavior: proxy` is rejected.
- `artifacts.behavior: proxy_cache_s3` is rejected.
- MongoDB/cachebox/S3 config is not required or initialized.

Verification:

```sh
cargo test config
```

## Milestone 4: Final Scope Audit

Problem: the implementation must match the requested phase, not the larger future product.

Desired behavior: explicit audit confirms phase-one scope and invariants.

Acceptance criteria:

- Search confirms no local malicious store implementation was added.
- Search confirms no cachebox, S3, proxy streaming, or memory metadata cache implementation was added.
- Tests or code review confirm policy is checked in metadata and artifact serving paths.
- Full test suite passes.

Verification:

```sh
rg -n "mongodb|cachebox|S3|proxy_cache_s3|memory cache|HashMap.*cache|artifact cache" src examples docs
cargo test
```

## Final Response Requirements

Report:

- Files changed.
- Commands run.
- Test results.
- Any commits made.
- Findings from the final scope audit.
- Residual risks or intentionally deferred product scope.
