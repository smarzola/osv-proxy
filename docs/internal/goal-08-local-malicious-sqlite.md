# Goal: Local Malicious SQLite Store

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Deliver a working local malicious-package store for `osv-proxy` using SQLite as
the first single-binary-friendly storage backend. Local mode must stop using
live OSV calls during install-request handling, while preserving the existing
policy semantics: only OSV `MAL-*` records are blocking inputs, exact allowlist
`bypass_osv` still skips malicious checks, and metadata generation plus artifact
serving both evaluate current policy.

Implement regular updates in two separate milestones. First deliver an explicit
sync command operators can schedule. Then add server-managed background sync
using the same sync engine. SQLite is the first backend despite older MongoDB
design notes; MongoDB-compatible storage can come later and must not distort
the SQLite implementation.

## Repository Rules

- Implementation code is explicitly requested for this goal.
- Follow `AGENTS.md`: correctness and performance are first-class because this
  project sits in the package-install path.
- Do not copy personal/private user rules into repository files.
- Do not revert unrelated user changes. You are not alone in this codebase.
- Keep npm and PyPI registry-specific parsing inside adapter/sync boundaries;
  keep policy ecosystem-neutral.
- Preserve the invariant that policy is checked during metadata generation and
  again during artifact serving.
- Local malicious mode must not make OSV network calls during install-request
  handling.
- Request-path local checks must be bounded indexed SQLite reads plus in-memory
  exact-version/range evaluation for the requested artifact.
- Do not pre-expand OSV ranges into every concrete npm/PyPI version during
  import. That makes imports too slow and is not the chosen design.
- Do not add MongoDB, mongolino, cachebox, S3 artifact caching, authentication,
  publishing, license policy, vulnerability severity policy, or broad scanning.
- If tests expose a real product gap, fix the product rather than weakening the
  test.
- At the end of each milestone, run verification, mark the milestone done in
  this file, commit the completed milestone, and report the commit hash before
  continuing.

## Target State

By the end, the repo should have:

- A supported local malicious data source backed by SQLite.
- A supported explicit sync command that bootstraps and incrementally updates
  npm and PyPI malicious OSV records from OSV GCS data dumps.
- A supported background sync mode in `serve`, implemented as a separate
  milestone on top of the explicit sync engine.
- Correct local evaluation of OSV exact `affected[].versions` and range
  `affected[].ranges[].events` for requested npm and PyPI package versions.
- A request path that uses no OSV network calls in local mode.
- SQLite WAL/read behavior configured so regular updates do not block normal
  install reads beyond normal short SQLite lock contention.
- Fail-closed behavior by default for missing, stale, corrupt, or unhealthy
  local malicious data.
- Tests and docs that use actual observed OSV dump shapes as fixtures, not
  invented advisory JSON.

## Current State

- `src/malicious.rs` has a `MaliciousChecker` trait and live `OsvHttpClient`
  implementation using `POST /v1/query` and `POST /v1/querybatch`.
- `src/policy.rs` already accepts malicious results without knowing whether
  they came from live OSV or another checker.
- `src/config.rs` exposes only live OSV settings under `policy.osv`.
- `docs/malicious-data.md` describes local storage as future work and sketches
  only exact concrete rows.
- `docs/mongolino-integration.md` states that active config does not expose a
  local malicious store.
- The repo does not currently parse OSV dump records, store advisories locally,
  evaluate OSV ranges, or sync OSV GCS dumps.

## Source Research Requirements

Before implementing sync parsing, inspect real upstream data:

- OSV data dump docs: `https://google.github.io/osv.dev/data/`
- OSV schema docs: `https://ossf.github.io/osv-schema/`
- OSV GCS ecosystem list:
  `https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt`
- npm and PyPI dump artifacts:
  `https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip`
  `https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip`
- Incremental metadata:
  `https://storage.googleapis.com/osv-vulnerabilities/npm/modified_id.csv`
  `https://storage.googleapis.com/osv-vulnerabilities/PyPI/modified_id.csv`

Use a tiny downloaded subset of real OSV records as test fixtures. The fixtures
must include at least one `MAL-*` record with explicit versions and at least one
record with ranges/events if such records exist in the current dumps. If the
current dumps do not contain a convenient `MAL-*` range record for npm/PyPI,
derive a minimal fixture from a real OSV range-shaped record and document that
derivation in the test module.

## Chosen Design

Configuration should make the source explicit. Use names that fit the repo once
you inspect existing config style, but target this shape unless implementation
evidence shows a better local convention:

```yaml
policy:
  osv:
    block_malicious: true
    source: local
    on_error: block
    local:
      sqlite_path: "./osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      background_sync: false
      sync_interval: "6h"
```

`source: live` should preserve the current default behavior. `source: local`
uses SQLite for malicious checks. Local mode must fail closed by default when
the database is missing, stale, unhealthy, or cannot evaluate a relevant record.

SQLite storage should keep raw advisories and normalized affected clauses rather
than pre-expanding all package versions:

- `advisories`: OSV id, modified/published/withdrawn timestamps, summary,
  raw JSON, source URL or dump source, imported timestamp.
- `affected_packages`: one row per advisory affected package, indexed by
  `(ecosystem, name)`.
- `affected_versions`: exact listed affected versions.
- `affected_ranges`: range type and owning affected package row.
- `affected_range_events`: ordered `introduced`, `fixed`, `last_affected`, and
  `limit` events.
- `sync_state`: ecosystem, source, high-water mark, last successful sync time,
  last attempted sync time, health status, and error summary.

The local checker should query by `(ecosystem, normalized_name)`, then evaluate
the requested version against exact versions and stored ranges in memory.

## Definition Of Done

The goal is complete only when:

1. `source: live` preserves current OSV API behavior and remains the default.
2. `source: local` uses SQLite and performs no OSV API calls during install
   request handling.
3. Local checks support exact OSV affected versions and OSV range event
   semantics for npm and PyPI requested versions.
4. The SQLite schema stores raw advisories and normalized affected package,
   exact-version, range, and sync-state data.
5. SQLite connections use WAL and appropriate busy timeout/read settings for
   nonblocking request-path reads during sync.
6. Missing, stale, corrupt, or unhealthy local data fails closed by default.
7. `osv-proxy malicious sync --config <path>` can bootstrap and incrementally
   update npm and PyPI data from OSV GCS dumps.
8. Server-managed background sync works as a separate milestone using the same
   sync engine and does not block request handling while it runs.
9. Tests use no live network by default and cover SQLite checker behavior,
   range evaluation, sync import, stale-data handling, and server local-mode
   request behavior.
10. At least one manual verification command demonstrates parsing current OSV
    dump shape from the real upstream source.
11. README, configuration docs, malicious-data docs, architecture/mongolino docs,
    and milestones reflect local SQLite support and MongoDB as future.
12. `cargo test` passes.
13. `cargo fmt --check` passes.
14. `cargo clippy --all-targets --all-features -- -D warnings` passes.
15. Milestone checkboxes in this file are marked `[x]` as work completes.
16. Each completed milestone has a focused commit.

## Milestone Checklist

When a milestone is complete:

1. Run the milestone's verification commands.
2. Update this checklist by changing the milestone from `[ ]` to `[x]`.
3. Add a short status note under that milestone with the date, exact commands
   run, and commit hash if available.
4. Commit the code, tests, docs, and checklist/status update with a focused
   commit message.
5. Report the commit hash in the goal-loop status before starting the next
   milestone.

- [x] Milestone 0: Baseline and real OSV data shape
- [x] Milestone 1: SQLite schema, config, and local checker
- [x] Milestone 2: npm/PyPI version range evaluation
- [ ] Milestone 3: Explicit OSV dump sync command
- [ ] Milestone 4: Request-path local mode integration
- [ ] Milestone 5: Background sync in serve
- [ ] Milestone 6: Docs, final regression, and release readiness

## Milestone 0: Baseline and Real OSV Data Shape

Problem:

- Local storage and sync must be grounded in actual OSV dump records. Invented
  fixtures risk missing real field shapes, withdrawn records, range types, or
  modified CSV behavior.

Desired behavior:

- Establish baseline test state.
- Inspect actual npm and PyPI OSV dump data and modified CSV shape.
- Capture small real fixtures for parser/range/sync tests.

Acceptance criteria:

- Baseline commands are run and recorded.
- Real OSV data dump docs and actual GCS artifacts are inspected.
- The repo contains tiny test fixtures derived from real current OSV records or
  a status note explaining exactly why a synthetic derivative was required for a
  specific shape.
- No request-path implementation behavior changes in this milestone except
  fixture files and the status note.
- Milestone status is marked done in this file and committed.

Likely files:

- `docs/internal/goal-08-local-malicious-sqlite.md`
- `tests/fixtures/osv/`
- possibly `src/malicious.rs` test fixtures if the repo's test style calls for
  inline fixtures instead of files.

Verification:

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note 2026-07-07:

- Inspected OSV data dump docs and OSV schema docs, plus current GCS artifacts
  from `ecosystems.txt`, npm/PyPI `modified_id.csv`, and npm/PyPI `all.zip`.
- Captured tiny fixtures from real current dump records:
  `MAL-2022-1122`, `MAL-2021-1`, `MAL-2023-10`, and `MAL-2022-7421`.
  Current dumps include MAL range records for npm (`SEMVER`) and PyPI
  (`ECOSYSTEM`), so no synthetic range derivative was needed.
- Commands run: `cargo test` in sandbox failed only on local socket binding with
  `Operation not permitted`; `cargo test` outside sandbox passed; `cargo fmt
  --check` passed; `cargo clippy --all-targets --all-features -- -D warnings`
  passed; OSV sampling used `curl -fsSL` for the listed GCS artifacts,
  `unzip -Z1`, `unzip -p`, and a read-only `python3` zip/JSON scan.
- Commit: `a2f3cdf`.

## Milestone 1: SQLite Schema, Config, and Local Checker

Problem:

- The policy engine can consume malicious results from any checker, but there is
  no local SQLite checker, no local config, and no schema for raw OSV advisories
  plus affected clauses.

Desired behavior:

- Add local-source configuration while keeping live OSV as default.
- Add SQLite storage initialization/migration and a checker that reads by
  normalized `(ecosystem, name)`.
- Configure SQLite for WAL and short busy waits appropriate for request-path
  reads.

Acceptance criteria:

- Config accepts explicit live/local source selection and rejects unknown nested
  local keys.
- Local config validates path, staleness, stale behavior, background sync flag,
  and sync interval.
- SQLite schema is initialized idempotently.
- Local checker returns `MaliciousHit` values for exact stored affected versions.
- Missing/corrupt/stale/unhealthy local DB maps to `MaliciousError` so the
  existing `policy.osv.on_error` fail-closed behavior applies.
- `check_many` uses package-grouped or batched indexed reads and preserves input
  order.
- No OSV network calls happen from the local checker.
- Milestone status is marked done in this file and committed.

Likely files:

- `Cargo.toml`
- `Cargo.lock`
- `src/config.rs`
- `src/malicious.rs`
- `src/lib.rs`
- new local store module if useful.

Verification:

```sh
cargo test config
cargo test malicious
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note 2026-07-08:

- Added explicit `policy.osv.source` config with `live` default and local
  SQLite settings for path, max staleness, stale behavior, background sync flag,
  and sync interval.
- Added idempotent SQLite schema initialization for raw advisories, affected
  packages, exact versions, ranges/events, and sync state. Connections configure
  WAL during initialization and a 5s busy timeout for local store access.
- Added `SqliteMaliciousChecker` for exact-version local hits, stale/missing or
  unhealthy store errors, range-row explicit errors pending Milestone 2, and
  order-preserving `check_many`.
- Commands run: `cargo test config` passed with 28 tests; `cargo test
  malicious` passed with 22 tests; `cargo fmt --check` passed. The first
  sandboxed `cargo test config` attempt failed to resolve `index.crates.io`;
  reran with approved Cargo network access to resolve new dependencies.
- Commit: `5c88d22`; fixup commit: `083756b`.

## Milestone 2: npm/PyPI Version Range Evaluation

Problem:

- OSV records may use exact `affected[].versions`, range events, or both.
  Local mode cannot rely on OSV's `/v1/query` to evaluate package/version
  matches.

Desired behavior:

- Implement OSV range event evaluation for requested npm and PyPI versions at
  read time.
- Avoid pre-expanding ranges into all registry versions during import.

Acceptance criteria:

- Exact affected versions still match by string equality according to OSV schema
  semantics.
- npm ranges are evaluated with npm-compatible semver ordering for supported
  OSV npm range types.
- PyPI ranges are evaluated with PEP 440-compatible ordering for supported PyPI
  range types.
- `introduced`, `fixed`, `last_affected`, and `limit` events are implemented
  according to OSV semantics.
- Unsupported relevant range type or unevaluable version returns a checker
  error rather than silently allowing.
- Tests cover before/inside/after range boundaries, multiple event intervals,
  `introduced: "0"`, fixed reopening behavior, `last_affected`, and limit.
- Milestone status is marked done in this file and committed.

Likely files:

- `Cargo.toml`
- `Cargo.lock`
- `src/malicious.rs`
- possible `src/version_range.rs` or `src/osv_range.rs`
- parser tests and fixtures.

Verification:

```sh
cargo test malicious
cargo test range
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note 2026-07-08:

- Added read-time OSV range evaluation for local SQLite checks without
  pre-expanding ranges into registry versions.
- npm `SEMVER` ranges use `node-semver`; PyPI `ECOSYSTEM` ranges use
  `pep440_rs`.
- Implemented `introduced`, `fixed`, `last_affected`, and `limit` event
  handling. Unsupported range types and unevaluable target/boundary versions
  return checker errors instead of silently allowing.
- Exact affected versions still match first by string equality, preserving the
  existing exact-version path.
- Commands run: `cargo test malicious` passed with 28 tests; `cargo test range`
  passed with 3 matching tests; `cargo fmt --check` passed. The first sandboxed
  test attempt failed to resolve `index.crates.io`; reran with approved Cargo
  network access to resolve new dependencies.
- Commit: this commit.

## Milestone 3: Explicit OSV Dump Sync Command

Problem:

- Operators need a deterministic way to populate and update local SQLite data
  without tying updates to request handling or server startup.

Desired behavior:

- Add `osv-proxy malicious sync --config <path>` using OSV GCS dumps.
- Bootstrap from npm/PyPI `all.zip` when needed.
- Incrementally update from per-ecosystem `modified_id.csv` after bootstrap.
- Apply updates atomically in SQLite without blocking readers beyond normal WAL
  writer contention.

Acceptance criteria:

- The command supports npm and PyPI only for this proxy scope.
- Sync imports only OSV `MAL-*` blocking records into local affected tables, but
  stores raw advisory JSON for all imported `MAL-*` records.
- Withdrawn records remove or disable affected rows so they no longer block.
- Updates for each advisory replace old rows atomically.
- `sync_state` advances only after successful import.
- Failed sync leaves the previous good snapshot usable and records health/error
  state.
- Tests use local fixture zips/CSVs and do not require live network.
- At least one manual verification command downloads or samples the current OSV
  upstream shape and is recorded in the status note.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/cli.rs`
- `src/malicious.rs`
- new sync module if useful
- `tests/fixtures/osv/`
- docs for command usage.

Verification:

```sh
cargo test malicious
cargo test cli
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 4: Request-Path Local Mode Integration

Problem:

- The server and CLI currently instantiate `OsvHttpClient` directly, so local
  mode would not be used even if storage and sync exist.

Desired behavior:

- Build the configured malicious checker once at the correct boundary for
  `serve`, `check`, and `eval`.
- In local mode, metadata filtering and artifact serving use SQLite checks and
  make no OSV network calls.

Acceptance criteria:

- `serve` uses a configured live or local malicious checker.
- `check` and `eval` use the configured live or local checker.
- Tests prove local mode blocks malicious npm/PyPI metadata entries and artifact
  requests from SQLite data.
- Tests prove local mode does not call OSV HTTP endpoints during request
  handling.
- Allowlist `bypass_osv` still skips local malicious checks.
- Existing live-mode behavior remains unchanged.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/server.rs`
- `src/cli.rs`
- `src/malicious.rs`
- `src/npm.rs`
- `src/pypi.rs`
- tests in existing modules.

Verification:

```sh
cargo test server
cargo test cli
cargo test npm
cargo test pypi
cargo test malicious
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 5: Background Sync In Serve

Problem:

- Operators should be able to run a single server binary that keeps local
  malicious data updated regularly, but this must be built after the explicit
  sync engine so it shares tested import behavior.

Desired behavior:

- Add optional background sync for `serve` when local mode enables it.
- Background sync uses the same sync engine as `malicious sync`.
- Request handling remains available while sync runs.

Acceptance criteria:

- `background_sync: true` starts a periodic sync task in `serve`.
- The first sync behavior is explicit and documented: either sync immediately on
  startup or wait for the interval, but local stale/missing fail-closed rules
  must still apply.
- Sync intervals are validated and bounded.
- A failed background sync records health state and does not crash the server
  unless config explicitly requires startup sync success.
- Tests prove request handling can read while a sync transaction is active or
  prove the lock contention is bounded with `busy_timeout`.
- The background task shuts down naturally when the server exits.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/server.rs`
- `src/config.rs`
- `src/malicious.rs`
- sync module tests.

Verification:

```sh
cargo test server
cargo test malicious
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 6: Docs, Final Regression, and Release Readiness

Problem:

- Local SQLite storage changes product configuration, deployment operations, and
  old docs that currently describe local storage as future work.

Desired behavior:

- Update user-facing docs and run full regression.
- Prepare the release commit according to `AGENTS.md`.

Acceptance criteria:

- README and docs describe live versus local malicious mode, sync command,
  background sync, staleness behavior, and failure behavior.
- `docs/malicious-data.md` describes raw advisory plus affected clause storage,
  exact/range evaluation, and SQLite WAL update behavior.
- `docs/mongolino-integration.md` is updated so MongoDB/mongolino remains a
  future backend rather than the active local store.
- `docs/milestones.md` marks local SQLite malicious storage complete and leaves
  MongoDB-compatible storage as future if still desired.
- `examples/basic/osv-proxy.yaml` remains simple and valid.
- `Cargo.toml` version and `CHANGELOG.md` are updated for release.
- Full regression passes or any environment-only failures are documented with
  evidence and rerun outside the sandbox as needed.
- Milestone status is marked done in this file and committed.

Likely files:

- `README.md`
- `docs/configuration.md`
- `docs/malicious-data.md`
- `docs/mongolino-integration.md`
- `docs/milestones.md`
- `examples/basic/osv-proxy.yaml`
- `Cargo.toml`
- `CHANGELOG.md`

Verification:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Final Verification

Before the goal is complete, run:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
```

Also run at least one functional local-mode smoke test that:

1. Creates a temporary SQLite malicious DB from fixture sync data.
2. Runs `osv-proxy check` with `source: local`.
3. Demonstrates a clean package/version allows.
4. Demonstrates a locally stored malicious package/version blocks.
5. Demonstrates no OSV API endpoint is required for the check.

## Release Requirement

After final verification passes:

1. Update `Cargo.toml` and `CHANGELOG.md` according to `AGENTS.md`.
2. Commit the release prep if not already committed.
3. Create a plain semver tag `vMAJOR.MINOR.PATCH`.
4. Push the release commit and tag together after explicit approval if the push
   requires sandbox escalation.
5. Verify the GitHub release workflow and release object.

## Final Response Required

When complete, report:

- target state achieved or not achieved;
- commits made;
- release tag and verification state;
- files changed;
- exact verification commands run and results;
- known residual risks or follow-up issues.
