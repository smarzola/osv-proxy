# Goal: Core Naive Redirect Proxy Foundation

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Implement the first foundation slice for `osv-proxy`: a Rust binary with YAML configuration, deterministic policy evaluation, naive OSV malicious checks, basic command routing, and testable primitives for metadata and artifact enforcement.

This phase is intentionally narrow. Implement naive OSV mode only, redirect artifact behavior only, no metadata cache, no local malicious store, no MongoDB, no cachebox, no proxy streaming, and no S3 artifact cache.

## Repository Rules

- Implementation code is now explicitly requested by the user.
- Keep the product centered on deterministic package policy enforcement, not broad security scanning.
- Keep npm and PyPI specifics in adapter modules. The core policy model must stay ecosystem-neutral.
- Do not add an in-process memory metadata cache.
- Preserve the invariant that policy is checked during metadata generation and checked again during artifact serving.
- Do not revert changes made by other workers. You are not alone in this codebase.

## Target State

- A Rust project exists and builds.
- The `osv-proxy` binary supports:
  - `serve --config <path>`
  - `check <ecosystem:name@version> --config <path>`
  - `config validate --config <path>`
- YAML config supports only settings needed for this phase plus sane defaults.
- Policy evaluation supports minimum age, missing publish time behavior, exact-version allowlist, manual exact or wildcard blocklist, and naive OSV `MAL-*` malicious blocking.
- Policy and config have focused unit tests.

## Current State

The repository is documentation-only. There is no Rust workspace, source tree, or test suite. Product docs define the intended model, but this milestone should simplify implementation shape where helpful.

## Definition of Done

1. `cargo test` passes.
2. Config defaults are conservative: `minimum_age = 72h`, `missing_publish_time = block`, `malicious.mode = naive`, `malicious.only_mal_ids = true`, `malicious.on_osv_error = block`, `artifacts.behavior = redirect`.
3. Config validation rejects unsupported phase-one settings: local malicious mode, metadata cache enabled, proxy artifacts, and S3 cache artifacts.
4. The policy engine is ecosystem-neutral and unit-tested.
5. Naive OSV client behavior is trait-backed and testable without live network calls.
6. `osv-proxy check` can evaluate a package/version with an optional publish time when supplied by tests or later adapters.

## Milestone Checklist

- [x] Rust scaffold and CLI
- [x] Configuration model and validation
- [x] Policy engine and decision model
- [x] Naive malicious client abstraction and tests
- [x] Command wiring and verification

Status note, 2026-07-05: Completed phase-one foundation as one scaffold slice. Verification commands run: `cargo fmt`, `cargo build`, `cargo test config`, `cargo test policy`, `cargo test malicious`, `cargo test`, `cargo fmt --check`, `cargo run -- config validate --config examples/phase1/osv-proxy.yaml`. Commit: included in the phase-one foundation commit; final hash reported by `git log`.

## Checkpoint Protocol

When a milestone is complete:

1. Run the milestone's verification commands.
2. Update this file by changing the milestone checkbox from `[ ]` to `[x]`.
3. Add a short status note with the date, exact commands run, and commit hash if available.
4. Commit the code, tests, docs, and status-note update with a focused commit message if committing is available in your workspace.
5. Report the commit hash or state that commits are unavailable before starting the next milestone.

## Milestone 1: Rust Scaffold and CLI

Problem: the repo has no implementation.

Desired behavior: `cargo build` produces an `osv-proxy` binary with the planned subcommands.

Acceptance criteria:

- Create a pragmatic single-crate Rust application unless a workspace is clearly needed.
- Include modules for config, policy, malicious checks, ecosystem/artifact modeling, server, npm, and PyPI boundaries.
- CLI parses `serve`, `check`, and `config validate`.
- Unsupported commands from the docs are not exposed yet.

Likely files:

- `Cargo.toml`
- `src/main.rs`
- `src/lib.rs`
- `src/cli.rs`

Verification:

```sh
cargo build
cargo test
```

## Milestone 2: Configuration Model and Validation

Problem: docs contain full v1 configuration, but phase one must expose only what is needed.

Desired behavior: YAML config loads with defaults and rejects unsupported phase-one modes.

Acceptance criteria:

- Support server listen and public base URL.
- Support npm registry URL, PyPI simple URL, PyPI files URL.
- Support policy minimum age, missing publish time, and naive malicious config.
- Support exact-version allowlist and blocklist.
- Support `metadata_cache.enabled: false` only.
- Support `artifacts.behavior: redirect` only.
- Do not add MongoDB, cachebox, S3, proxy mode, or local malicious implementation code.

Likely files:

- `src/config.rs`

Verification:

```sh
cargo test config
```

## Milestone 3: Policy Engine and Decision Model

Problem: all ecosystem adapters must share one deterministic policy evaluator.

Desired behavior: policy takes a canonical artifact and returns a structured decision.

Acceptance criteria:

- Implement canonical `Ecosystem`, `Artifact`, `ArtifactHashes`, `Decision`, and `DecisionReason`.
- Implement canonical identity format `{ecosystem}:{name}@{version}`.
- Implement evaluation order from `docs/policy.md`.
- Allowlist entries are exact-version only.
- Blocklist supports exact versions and `*`.
- Missing publish time follows config.

Likely files:

- `src/artifact.rs`
- `src/policy.rs`

Verification:

```sh
cargo test policy
```

## Milestone 4: Naive Malicious Client Abstraction and Tests

Problem: naive mode can call OSV in request handling, but tests must not depend on the live OSV service.

Desired behavior: policy asks a trait-backed malicious checker and only blocks `MAL-*` IDs.

Acceptance criteria:

- Define a `MaliciousChecker` trait.
- Implement an OSV HTTP client for `/v1/query`.
- Unit tests use a fake checker.
- Non-`MAL` advisories do not block when `only_mal_ids = true`.
- OSV errors follow `on_osv_error`.
- Exact allowlist with `bypass_malicious = true` skips malicious checks.

Likely files:

- `src/malicious.rs`
- `src/policy.rs`

Verification:

```sh
cargo test malicious
cargo test policy
```

## Milestone 5: Command Wiring and Verification

Problem: users need simple commands to validate config and inspect decisions.

Desired behavior: CLI loads config, validates phase-one constraints, initializes the policy engine, and can report decisions.

Acceptance criteria:

- `config validate --config <path>` exits success for supported configs and failure for unsupported modes.
- `check npm:lodash@4.17.21 --config <path>` prints a structured decision.
- Tests cover parser behavior for npm scoped names and PyPI normalization.

Likely files:

- `src/cli.rs`
- `src/main.rs`
- `src/lib.rs`

Verification:

```sh
cargo test
cargo run -- config validate --config examples/phase1/osv-proxy.yaml
```

## Final Response Requirements

Report:

- Files changed.
- Commands run.
- Test results.
- Any commits made.
- Residual risks or intentionally deferred product scope.
