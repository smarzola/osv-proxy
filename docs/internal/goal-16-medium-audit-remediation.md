# Goal: Address The Actionable Medium Audit Findings

Work in `/Users/smarzola/projects/osv-proxy`.

Resolve the outstanding, currently addressable medium-severity findings from
the adjudicated 2026-07-11 repository audit. The resulting proxy must bound
process-wide request and upstream concurrency, expose truthful shared-service
health/readiness behavior, shut down gracefully, reject invalid network
configuration before serving, and build through reproducible CI/release inputs.
Add these capabilities through clear runtime and readiness boundaries instead
of further concentrating responsibilities in the existing routing and OSV
storage modules.

Source of truth: `docs/internal/audit-2026-07-11.md`, especially its
2026-07-12 medium-finding dispositions.

Starting branch: `feat/medium-audit-remediation`.
Base branch and commit: `main` at `ec2004f` (`v0.7.2`).
Primary Conventional Commit type: `feat`.

## Target State

When this goal is complete:

- The process has configurable, validated global ingress and egress
  concurrency limits. Saturation is bounded and has deterministic behavior;
  background OSV synchronization cannot consume the install-path budget.
- `/healthz` reports process liveness without contacting dependencies, while
  `/readyz` truthfully reflects whether the configured policy source can make
  decisions. Local mode accounts for every supported ecosystem's data health
  and freshness. The server handles termination signals with graceful drain.
- Authentication, TLS, client rate limiting, and public-edge access control are
  explicitly delegated to a trusted gateway/reverse proxy. A public bind emits
  an actionable warning rather than changing compatibility or requiring an
  acknowledgement flag.
- Invalid bind addresses and malformed or unsafe configured HTTP endpoints fail
  during configuration validation with field-specific errors. Existing valid
  configurations remain compatible, including private HTTP fixture/mirror
  endpoints.
- CI and release actions are immutable, the Rust toolchain and moving language
  inputs are pinned in the repository/workflows, and release provenance records
  the effective toolchain without weakening existing gates.
- New admission, lifecycle, and readiness behavior lives behind focused
  boundaries. Existing shared clients and the canonical artifact-delivery path
  remain intact; refactoring is justified by concrete responsibility or
  invariant boundaries rather than file length.
- The audit records current evidence-based dispositions for all eight original
  medium findings.

## Current-State Evidence

Verified before this goal was written:

- `docs/internal/audit-2026-07-11.md`: `OPS-01`, `OPS-02`, `CI-02`, `CFG-01`,
  and narrowed `ARCH-01` remain open; `CI-01` is resolved, `PERF-04` lacks
  workload evidence, and `TEST-01` is accepted design.
- `src/server.rs::router` has only an 8 KiB request-body layer; there is no
  process-wide admission limit, health/readiness route, signal drain, or
  separate runtime boundary.
- Registry adapters contain request-local fan-out caps and Reqwest timeouts,
  but no shared process-wide egress budget.
- `src/malicious.rs` stores per-ecosystem local sync health and timestamps, but
  exposes no server readiness summary.
- `Config::validate` validates policy and trusted artifact origins but not
  `server.bind`, `server.public_base_url`, OSV API URL, or registry endpoints.
- `.github/workflows/ci.yml` and `release.yml` use movable action major tags,
  Rust `stable`, Node `lts/*`, and an unpinned uv tool version; several other
  language/package-manager versions are already exact.
- Application state already owns reusable registry and artifact clients, so
  that part of the original architecture finding is resolved.
- The worktree began with the user-approved medium-finding adjudication edit to
  `docs/internal/audit-2026-07-11.md`; it belongs to this goal.

Unknowns that may affect implementation details but not the target state:

- The smallest safe egress-budget abstraction across buffered metadata,
  streamed artifacts, and background sync must be selected from the concrete
  request lifetimes. A permit must cover the relevant network/body lifetime,
  not merely client construction.
- The exact immutable action revisions and pinned tool versions must be verified
  from their authoritative upstream repositories before workflow edits.

## Constraints And Non-Goals

Follow `AGENTS.md`.

- Preserve deterministic policy behavior, route compatibility, configuration
  defaults, response bodies, and artifact streaming semantics.
- Existing YAML must remain valid. New tuning fields must have conservative,
  documented defaults and reject zero or otherwise unusable values.
- Do not implement authentication, TLS termination, client-identity rate
  limiting, firewall/network policy, or a public-service acknowledgement flag.
- Do not add metadata caching or request coalescing without workload evidence.
- Do not make package-manager E2Es silently skip missing required CLIs.
- Do not add a telemetry backend merely to satisfy a checklist. Logs and health
  behavior must be truthful and must not expose secrets or full credentialed
  URLs.
- Do not perform a broad file-size-driven rewrite. Extract only concrete
  admission, lifecycle, readiness, configuration-validation, or repeated
  invariant boundaries needed by this goal.
- Do not change the SQLite schema or policy decision semantics unless required
  for a truthful read-only readiness query and backed by compatibility tests.
- Preserve unrelated user changes and use Apple Container rather than Docker if
  containerized verification becomes necessary.

## Authorization And Decisions

This goal authorizes repository inspection, in-scope local edits, focused
Conventional Commit checkpoints, branch-local dependency/lockfile changes, and
relevant non-destructive verification.

It does not authorize pushing, opening or merging a pull request, publishing a
release, destructive actions, secrets or permission changes, or material scope
expansion. Continue through routine implementation choices using repository
evidence. Ask only when an ambiguity materially changes public behavior,
architecture, data compatibility, security posture, or authorization.

Before declaring a blocker, exhaust safe in-scope alternatives. If still
blocked, record the condition, evidence, and smallest required decision or
external change without claiming completion.

## Success Criteria

The goal is complete only when:

1. Configurable global ingress and egress limits are validated and enforced by
   concurrency regressions, including deterministic saturation behavior and
   separation of background-sync work from install traffic.
2. Liveness, dependency-aware readiness, local per-ecosystem health/freshness,
   non-loopback gateway warnings, and graceful draining are implemented and
   tested without changing registry route behavior.
3. Every configured bind/HTTP endpoint is validated at load time with focused
   positive and negative tests, while supported private HTTP mirrors and local
   fixtures remain valid.
4. CI and release workflows use verified immutable action revisions, a
   committed exact Rust toolchain, exact moving tool inputs, and recorded build
   provenance; existing format, Clippy, RustSec, test, build, and release gates
   remain present.
5. The implementation introduces focused runtime/readiness/configuration
   boundaries and removes concrete duplication encountered by the work without
   creating a second production routing or artifact-delivery path.
6. Operator documentation states the gateway boundary, tuning behavior,
   readiness contract, shutdown behavior, endpoint constraints, pinned test
   prerequisites, and what telemetry remains unimplemented.
7. The audit dispositions cite the delivered evidence and no resolved or
   accepted item is presented as an outstanding medium defect.
8. Every milestone passes adversarial review, verification, and a focused
   checkpoint commit; final verification and an independent final audit pass.

## Milestones

- [x] Milestone 1: Validated endpoint configuration and process-wide budgets
- [x] Milestone 2: Truthful health/readiness, gateway warning, and graceful drain
- [x] Milestone 3: Immutable CI/release inputs and toolchain provenance
- [x] Milestone 4: Operational boundaries, documentation, and audit closure

### Checkpoint Protocol

At the end of each milestone:

1. Satisfy its acceptance criteria.
2. Run its verification commands and inspect the results.
3. Freeze main-agent writes and pass the diff plus verification evidence to the
   retained read-only adversarial reviewer. Repair and re-review until no
   blocking finding remains.
4. Mark its checkbox `[x]` and add a dated status note with the outcome, exact
   commands, and results.
5. Commit implementation, tests, docs, and this goal update together using a
   focused Conventional Commit.
6. Report the resulting commit hash before starting the next milestone.

If verification fails, leave the milestone unchecked and do not create its
checkpoint commit. Diagnose and repair in-scope failures rather than weakening
tests. A commit cannot contain its own hash; report the hash after committing.

## Milestone 1: Validated Endpoint Configuration And Process-Wide Budgets

Why this matters:

- Invalid endpoints currently fail late, and concurrent valid traffic can
  exceed any process-wide resource envelope despite request-local fan-out caps.

Acceptance criteria:

- Bind and HTTP endpoint fields fail validation early with field-specific
  errors for malformed addresses, unsupported schemes, missing hosts,
  credentials, queries/fragments, and endpoint-specific unusable paths.
- Supported public endpoints, private HTTP mirrors, loopback fixtures, and
  intentional base paths remain valid.
- Backward-compatible configuration exposes nonzero ingress, aggregate egress,
  per-upstream, background-sync, queue/deadline tuning as justified by the
  implementation; invalid relationships or zero budgets are rejected.
- Ingress overload and egress saturation are deterministic and tested. Egress
  permits cover buffered or streamed response lifetimes as applicable.
- Background synchronization uses its own bounded budget and cannot consume the
  install-path egress allocation.

Likely touchpoints (non-exhaustive):

- `src/config.rs`
- `src/server.rs`
- registry/OSV clients and `src/artifacts.rs`
- a focused runtime/admission module
- `examples/basic/osv-proxy.yaml`

Verification:

```bash
cargo test --locked config
cargo test --locked server
cargo test --locked artifacts
cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml
```

Status: Completed 2026-07-12. Network endpoint validation now covers every
configured HTTP field plus compatible numeric/hostname bind syntax. Runtime
budgets enforce immediate ingress admission, actual-operation install egress,
and independent background egress; streamed bodies retain permits and all HTTP
overload paths return `503` with `Retry-After`.

Verification:

- `cargo test --locked config`: 45 passed, 0 failed.
- `cargo test --locked server`: 40 passed, 0 failed.
- `cargo test --locked artifacts`: 19 passed, 0 failed.
- `cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml`:
  configuration is valid.
- `git diff --check`: passed.
- Retained adversarial review: three rounds; no blocking findings remain.

Decision (2026-07-12): use one aggregate install-path egress budget shared by
all registry, artifact, and live OSV clients, plus a separate background-sync
egress budget. Existing adapter-local fan-out caps remain the per-upstream
ceilings. Do not add independently configurable per-upstream quotas without
workload evidence because fixed partitions can strand capacity; residual
cross-ecosystem starvation risk remains documented for future measurement.

Review notes (2026-07-12): the first review rejected request-level egress
admission because it did not bound actual fan-out and found numeric-only bind
validation incompatible. The repair moved permits to every outbound operation,
retained artifact permits through stream lifetime, separated background dump
requests, and restored hostname binds. The second review required strict DNS
hostname syntax and one overload contract across adapter and live-policy error
mapping; the repair added central request-task overload tracking and stable
`503` plus `Retry-After` behavior.

## Milestone 2: Truthful Health, Readiness, Gateway Warning, And Graceful Drain

Why this matters:

- A shared deployment needs to distinguish a live process from one unable to
  enforce its configured policy and must drain active artifact streams during
  termination.

Acceptance criteria:

- `/healthz` is dependency-free and reports liveness.
- `/readyz` is truthful for both live and local OSV modes. Local readiness
  evaluates every supported ecosystem's active generation, recorded health,
  and staleness using the same configured policy boundary as request handling.
- Health routes do not collide with registry fallback routing and use stable,
  documented status/body contracts.
- The production serve path handles termination signals and gives in-flight
  responses a bounded graceful-drain opportunity.
- Non-loopback startup emits one actionable warning that delegates auth, TLS,
  rate limiting, and edge policy to a trusted gateway without rejecting the
  configuration.
- Focused tests cover ready/unready local states, live mode, route precedence,
  drain behavior, and warning classification without depending on real signals
  or external services.

Likely touchpoints (non-exhaustive):

- a focused runtime/readiness module
- `src/server.rs`
- `src/malicious.rs`
- `docs/registry-behavior.md`
- `docs/observability.md`

Verification:

```bash
cargo test --locked server
cargo test --locked malicious
```

Status: Completed 2026-07-12. Explicit health routes precede registry fallback;
local readiness evaluates all seven active datasets through policy-equivalent
health and staleness rules. Shared listener startup warns for public binds.
SIGINT/SIGTERM initiate graceful drain, and forced cancellation reaches both
pre-response work and active artifact streams after the 30-second opportunity.

Verification:

- `cargo fmt --check`: passed.
- `cargo test --locked server`: 47 passed, 0 failed.
- `cargo test --locked malicious`: 75 passed, 0 failed.
- `git diff --check`: passed.
- Retained adversarial review: three rounds; no blocking findings remain.

Decision (2026-07-12): liveness is dependency-free. Live OSV mode is ready
after validated startup because request-time OSV failures still follow the
configured fail-open/fail-closed policy. Local mode reports all seven ecosystem
states and is ready only when every ecosystem can be evaluated under the same
dataset-version, health, and staleness rules as policy checks. Graceful drain is
bounded at 30 seconds in production and tested through an injectable shutdown
future.

## Milestone 3: Immutable CI/Release Inputs And Toolchain Provenance

Why this matters:

- Movable action and toolchain selectors allow verification and release output
  to change without a repository diff.

Acceptance criteria:

- Every GitHub Action reference in CI/release is pinned to a verified commit SHA
  with a readable version comment.
- Rust uses one exact committed toolchain across local, CI, release validation,
  and release builds. Node and uv no longer use moving selectors; other exact
  package-manager pins are preserved.
- Release output records the effective Rust/compiler and relevant build
  toolchain versions in provenance or a shipped inventory without weakening
  archive/checksum behavior.
- Workflow syntax and all existing validation/build/release dependencies remain
  correct, with duplicated toolchain setup kept consistent through a concrete
  shared source or verification test where practical.

Likely touchpoints (non-exhaustive):

- `rust-toolchain.toml`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- a workflow consistency test/script if justified

Verification:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
git diff --check
```

Status: Completed 2026-07-12. All action references are immutable SHAs; Rust,
Node, uv, and existing package-manager inputs are exact. CI/release share the
committed Rust 1.97.0 toolchain, locked Clippy, RustSec, and test gates. Release
archives ship `TOOLCHAIN.txt`, and an integration regression rejects moving
workflow inputs.

Verification:

- Rust 1.97.0 `cargo fmt --check`: passed.
- Rust 1.97.0 `cargo clippy --all-targets --all-features --locked -- -D
  warnings`: passed.
- Rust 1.97.0 `cargo test --locked --lib`: 301 passed, 0 failed.
- Rust 1.97.0 `cargo test --locked --test workflow_reproducibility`: 1 passed.
- Normal-host package-manager E2Es: 12 passed; Maven and Gradle stopped only at
  their explicit missing local CLI prerequisites, which required CI provisions.
- `git diff --check`: passed.
- Retained adversarial review: two rounds plus final-diff check; no blocking
  findings remain.

Evidence note (2026-07-12): action revisions were resolved read-only from each
authoritative GitHub repository. Rust `1.97.0` was selected from the official
stable manifest dated 2026-07-09; Node `24.18.0` is the current pinned LTS line;
uv `0.11.28` came from the authoritative latest-release API. Because the host
Homebrew toolchain has no `rustup`, the official Rust 1.97.0 standalone archive
was downloaded to a temporary prefix, verified against its published SHA-256,
and used directly for the exact format, Clippy, and test gates without changing
the machine-global toolchain. Archive:
`https://static.rust-lang.org/dist/rust-1.97.0-aarch64-apple-darwin.tar.xz`;
SHA-256: `44f35089605c8ab8cafb7d21e3497a57c24ae48e789729b5924fd2719dae0388`.
The temporary prefix was created by the archive's `install.sh --prefix ...
--disable-ldconfig`; verification prepended that prefix's `bin` directory to
`PATH` for each Cargo command.

Verification note (2026-07-12): under Rust 1.97.0, format, strict Clippy, 301
unit tests, and the workflow reproducibility integration test pass. With normal
host access, 12 of 14 package-manager E2Es also pass. The remaining Maven and
Gradle E2Es stop at their existing explicit
prerequisite assertions because this host has no functional Java, `mvn`, or
`gradle`; required CI provisions the exact Temurin/Maven/Gradle versions.

## Milestone 4: Operational Boundaries, Documentation, And Audit Closure

Why this matters:

- Operational behavior must be understandable from public docs, and the
  implementation should leave clearer responsibility boundaries rather than
  adding more route/storage concentration.

Acceptance criteria:

- Admission, lifecycle, readiness, and endpoint validation have focused module
  or API ownership, with no duplicated production router or artifact path.
- Any cross-registry invariant duplication touched by this goal is centralized
  when doing so reduces demonstrated drift risk; no broad rewrite is performed
  solely to reduce line counts.
- Public documentation matches implemented limits, gateway responsibilities,
  health/readiness semantics, graceful shutdown, endpoint restrictions, and
  the exact verification prerequisites.
- `docs/observability.md` clearly separates implemented signals from target
  telemetry.
- The audit's current disposition table and finding sections point to the
  delivered behavior and accurately classify remaining non-goals or residual
  risks.

Likely touchpoints (non-exhaustive):

- `src/server.rs` and focused runtime/readiness/configuration modules
- `docs/configuration.md`
- `docs/registry-behavior.md`
- `docs/observability.md`
- `docs/internal/audit-2026-07-11.md`
- this goal file

Verification:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml
git diff --check
```

Status: Completed 2026-07-12. Public docs now describe the gateway boundary,
endpoint validation, limits and overload behavior, health/readiness JSON,
graceful/forced drain, exact local prerequisites, and implemented versus target
telemetry. Architecture documents focused runtime/readiness ownership. The
audit closes or reclassifies every original medium item with checkpoint
evidence while preserving original snapshot sections.

Verification:

- `cargo fmt --check`: passed.
- `cargo test --locked --test workflow_reproducibility`: 1 passed, 0 failed.
- `cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml`:
  configuration is valid.
- `git diff --check`: passed.
- Retained adversarial review: two rounds; no blocking findings remain.

Decision (2026-07-12): `runtime.rs` owns admission, overload propagation,
response-lifetime permits, and forced lifecycle control; `readiness.rs` owns the
public readiness model; `malicious.rs` exposes one read-only ecosystem readiness
API that reuses policy health invariants. This is the concrete architecture
boundary justified by the operational work. A broad router/storage split is no
longer classified as an active medium defect without a demonstrated drift or
change target.

## Final Verification

Run from `/Users/smarzola/projects/osv-proxy`:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml
cargo audit --file Cargo.lock
git diff --check
```

Inspect every failure and repair in-scope regressions rather than weakening
tests. An unrelated pre-existing failure must be recorded with the command,
result summary, and evidence that this branch did not cause it.

## Resume Protocol

On resume, first read this file, `AGENTS.md`, `git status`, milestone notes, and
recent commits. Verify completed checkpoints and continue from the first
unchecked milestone without redoing completed work. New evidence may refine
implementation details but must not silently weaken the target state or success
criteria.

## Final Report

Lead with `Achieved` or `Not achieved`, then report:

- target state and success-criteria status;
- milestone checkpoint commits;
- files changed;
- exact verification commands and results;
- reviewer rounds and final-auditor disposition;
- residual risks or unauthorized external delivery steps.
