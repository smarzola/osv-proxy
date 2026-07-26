# Goal: Local-Only OSV With Revision-Safe Metadata Caching

Work in `/Users/smarzola/projects/osv-proxy`.

Make package-install decisions use one deterministic local OSV data path and
serve repeated package metadata without repeating expensive parsing, SQLite
policy evaluation, filtering, or serialization. Remove live OSV request-path
evaluation, synchronize local data automatically by default every hour, and
make newly synchronized advisories invalidate cached filtered metadata without
adding a cache freshness window.

Source of truth: this prompt and the user-approved design discussion in the
current Codex task.

Starting branch: `feat/in-memory-metadata-cache`.
Base branch and commit: `main` at `ac47af9`.
Primary Conventional Commit type: `feat`.

## Target State

When this goal is complete:

- Local SQLite is the only OSV policy source. Package-install, `check`, and
  `eval` paths do not call the live OSV query API, and obsolete live-mode
  configuration and documentation are removed.
- Local background synchronization is enabled by default and repeats one hour
  after a fully successful cycle. Explicit preseed synchronization and the
  option to disable serving-process background synchronization remain
  available.
- Each ecosystem has a durable content revision advanced in the same SQLite
  transaction that makes new, changed, or withdrawn OSV records visible.
  Filtered metadata cached against an older revision cannot be served after a
  successful content-changing sync.
- Supported metadata routes cache the complete policy-filtered canonical HTTP
  representation in process. Repeated requests share immutable response bytes,
  identical misses coalesce around the complete fetch/filter operation, and
  unique fills are concurrency-bounded.
- Cache memory is bounded by total weighted capacity and maximum entry size;
  entries expire by TTL; unsuccessful or oversized responses are not retained;
  client representation headers are part of cache identity or are applied
  after the canonical cached representation so response semantics remain
  correct.
- Direct package artifact delivery continues to perform its existing current
  policy check before redirecting or fetching upstream artifact bytes.

## Current-State Evidence

Verified before this prompt was written:

- `src/config.rs::OsvSource` still supports `local` and `live`;
  `configured_osv_checker_with_budgets` selects `OsvHttpClient` for live mode.
- `LocalOsvConfig::default` sets `background_sync: false`,
  `sync_interval: 6h`, and fail-closed staleness behavior.
- `src/malicious.rs::sync_incremental` downloads per-ecosystem
  `modified_id.csv`, retrieves changed advisory JSON, and commits advisory
  replacement plus `sync_state` in one SQLite transaction.
- Incremental sync mutates the active generation rather than replacing its ID,
  so `active_generation_id` alone cannot invalidate a policy-result cache.
- `src/server.rs::AppState` already owns reusable registry clients and is the
  natural owner of one process-wide metadata cache.
- The server admits 128 active requests by default while local SQLite checks
  are limited to eight blocking operations. Current adapters parse, construct,
  filter, and serialize metadata independently for every request.
- `docs/performance.md` records up to 133.9 ms added local-policy latency for a
  representative metadata route and 81.6 MiB RSS after one large React
  metadata response.
- `docs/milestones.md` identifies metadata caching as future work and requires
  policy to remain effective when cached metadata exists.

Unknowns that may affect implementation details but not the target state:

- The smallest cacheable-response boundary across all registry protocols must
  be selected from the existing route parsers and conditional/range response
  behavior. Artifact streams must never enter this cache.
- Exact cache defaults should be conservative and validated against current
  maximum metadata body sizes; total weighted capacity is a cache payload
  budget rather than a hard process RSS limit.

## Constraints And Non-Goals

Follow `AGENTS.md`; correctness and performance are first-class requirements.

- Preserve all supported package-manager routes, metadata filtering semantics,
  artifact redirect/proxy behavior, fail-closed local readiness, SQLite WAL
  concurrency, and explicit `osv sync` behavior.
- Preserve existing SQLite databases through an automatic additive schema
  migration. Do not require operators to rebuild a valid local store.
- Keep cache values policy-filtered, not merely raw upstream metadata. A hot
  package must not repeat parsing, policy lookup, filtering, or serialization.
- A content-changing sync must invalidate cached policy output. Cache TTL must
  not be the mechanism that eventually discovers a new vulnerability.
- Do not cache artifact bodies, health/readiness responses, unsupported
  methods, or permanent error/denial results.
- Do not add distributed caching, persistence, stale-while-revalidate, negative
  caching, S3/cachebox integration, hot configuration reload, authentication,
  publishing, or a metrics backend.
- Preserve unrelated user changes. Use Apple Container rather than Docker if
  containerized verification becomes necessary.
- Implement the smallest coherent complete design. Prefer a focused cache
  boundary in server state and established route/policy interfaces over
  adapter-wide frameworks or speculative backend abstractions.
- Do not confuse simple with partial: include migration, synchronization races,
  bounded memory/concurrency, response variants, tests, documentation, and
  compatibility cleanup required by the target state.

## Authorization And Decisions

This goal authorizes repository inspection, in-scope local edits, dependency
and lockfile changes, focused Conventional Commit checkpoints, branch-local
tests, and adversarial reviewer subagents.

It does not authorize pushing, opening or merging a pull request, publishing a
release, destructive actions, secrets or permission changes, or material scope
expansion. Continue through routine implementation choices using repository
evidence. Ask only when ambiguity materially changes public behavior,
architecture, data compatibility, security posture, or authorization.

Before declaring a blocker, exhaust safe in-scope alternatives. If still
blocked, record the condition, evidence, and smallest required decision or
external change without claiming completion.

Decision: remove live OSV policy evaluation rather than preserve an alternate
remote request path. Local data freshness is the OSV export delay plus the
configured polling interval and sync duration.

Decision: background sync remains configurable but defaults to enabled with a
one-hour interval.

Decision: add a monotonically increasing per-ecosystem content revision and
advance it transactionally only when a bootstrap or incremental import can
change visible advisory content. A cache lookup validates local store health
and uses the current revision before accepting an entry.

Decision: cache complete filtered metadata representations using shared
immutable bytes. The cache identity includes every request input that changes
the representation. Direct artifact routes remain outside the cache and keep
their second policy check.

## Success Criteria

The goal is complete only when:

1. Live OSV request-path behavior and configuration are removed; local SQLite
   is the sole checker used by serve/check/eval, with focused compatibility and
   invalid-configuration tests.
2. Background sync defaults to enabled and `1h`, while explicit sync and an
   explicit `background_sync: false` configuration remain valid and tested.
3. Existing SQLite databases migrate additively to a durable per-ecosystem
   content revision. Bootstrap and changed incremental commits advance it;
   no-change cycles do not; failed syncs do not; policy reads observe only
   committed revisions.
4. Repeated identical metadata requests perform one complete upstream
   fetch/filter/serialization fill and then return byte-shared cache hits.
   Concurrent identical misses coalesce and unique fills are bounded.
5. A content-changing local OSV sync makes older filtered entries unusable
   immediately for new requests; the first request at the new revision
   refilters and newly vulnerable versions are excluded.
6. Cache TTL, total weighted capacity, maximum entry size, enable/disable
   behavior, representation identity, unsuccessful-response behavior, and
   artifact-route exclusion are validated by focused tests.
7. All existing package-manager behavior and the artifact second-check
   invariant remain covered. Operator-facing docs and examples state only
   implemented local-only OSV and in-process metadata-cache behavior.
8. Every milestone passes narrow verification and retained adversarial review
   before a focused checkpoint commit; final verification and a fresh
   independent audit are clean.

## Milestones

- [ ] Milestone 1: Local-only OSV synchronization and transactional revisions
- [ ] Milestone 2: Bounded revision-aware filtered metadata cache
- [ ] Milestone 3: Integration coverage, operator documentation, and regression
  closure

### Checkpoint Protocol

At the end of each milestone:

1. Satisfy its acceptance criteria.
2. Run its verification commands and inspect the results.
3. Freeze main-agent writes and obtain adversarial read-only review from the
   retained reviewer. Repair and re-review until no blocking finding remains.
4. Mark its checkbox `[x]` and add a dated status note containing the outcome,
   exact commands, results, and review disposition.
5. Commit the implementation, tests, docs, and this goal update together using
   a focused Conventional Commit.
6. Report the resulting commit hash before beginning the next milestone.

If verification fails, leave the milestone unchecked and do not create its
checkpoint commit. Diagnose and repair in-scope failures rather than weakening
tests. A commit cannot contain its own hash; report the hash after committing.

## Milestone 1: Local-Only OSV Synchronization And Transactional Revisions

Why this matters:

- The cache needs one authoritative policy-data revision, and local-only mode
  must offer a complete freshness/readiness path before live mode disappears.

Acceptance criteria:

- Local SQLite is the only configured OSV checker. Removed live fields are
  rejected rather than silently ignored, and remaining configuration has clear
  defaults.
- Background sync defaults to enabled and one hour; disabled background sync
  and explicit preseed sync remain functional.
- Existing and fresh schemas expose content revision. Successful content
  changes advance it atomically; no-op and failed cycles do not.
- The incremental high-watermark boundary cannot miss distinct records sharing
  the same modified timestamp.

Likely touchpoints (non-exhaustive):

- `src/config.rs`
- `src/malicious.rs`
- `src/readiness.rs`
- `src/server.rs`
- `src/cli.rs`

Verification:

```bash
cargo test --locked config
cargo test --locked malicious
cargo test --locked readiness
cargo test --locked server
cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml
```

Status: Not started.

## Milestone 2: Bounded Revision-Aware Filtered Metadata Cache

Why this matters:

- Avoiding only upstream I/O still repeats the high-cardinality work and memory
  amplification that motivated caching.

Acceptance criteria:

- One cache in application state admits only supported metadata GET routes and
  stores complete filtered responses in immutable shared bytes.
- Identical concurrent misses coalesce around the complete fill. Hits do not
  repeat upstream fetch, parsing, policy checks, or serialization.
- Cache capacity, maximum entry size, TTL, and unique-fill concurrency are
  bounded and validated. Disabled, unsuccessful, and oversized paths do not
  retain entries.
- Policy revision and all material representation inputs participate in cache
  identity. A changed revision cannot return the previous response.
- Artifact routes remain uncached and keep their current policy-before-delivery
  behavior.

Likely touchpoints (non-exhaustive):

- `src/server.rs`
- a focused metadata-cache module
- `src/response.rs`
- `src/config.rs`
- `Cargo.toml` and `Cargo.lock`

Verification:

```bash
cargo test --locked metadata_cache
cargo test --locked server
cargo test --locked npm
cargo test --locked pypi
cargo test --locked cargo
cargo test --locked go
cargo test --locked nuget
cargo test --locked rubygems
cargo test --locked maven
```

Status: Not started.

## Milestone 3: Integration Coverage, Documentation, And Regression Closure

Why this matters:

- The cache and source removal cross every package-manager route and operator
  setup; completion requires truthful public behavior and full regression
  evidence.

Acceptance criteria:

- A hermetic integration test demonstrates that a newly committed OSV finding
  changes the revision and invalidates a previously allowed cached metadata
  response.
- Package-manager E2Es and unit tests preserve supported resolver behavior,
  response variants, and artifact policy rechecks.
- README, configuration, OSV-data, architecture, performance, policy,
  observability, product, milestone, and example documentation describe only
  current local-only and bounded in-memory cache semantics.
- Live-mode symbols and claims are absent outside historical internal goal
  records where changing history would be misleading.

Likely touchpoints (non-exhaustive):

- `tests/package_manager_e2e.rs`
- `README.md`
- `docs/*.md`
- `examples/basic/osv-proxy.yaml`

Verification:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked --lib
cargo test --locked --test workflow_reproducibility
cargo test --locked --test package_manager_e2e
cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml
git diff --check
```

Status: Not started.

## Final Verification

Run from `/Users/smarzola/projects/osv-proxy`:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml
git diff --check
```

Inspect every failure. Fix in-scope regressions rather than weakening tests. An
unrelated pre-existing failure may be reported only with the exact command,
result summary, and evidence that this goal did not cause it.

## Resume Protocol

On a resumed session, first read this prompt, `AGENTS.md`, `git status`, the
milestone status notes, and recent commits. Verify completed checkpoints and
continue from the first unchecked milestone without redoing completed work.
New evidence may refine implementation details but must not silently weaken
the target state or success criteria.

## Final Report

Lead with `Achieved` or `Not achieved`, then report:

- target state and success criteria status;
- branch and milestone checkpoint commits;
- files changed;
- exact verification commands and results;
- adversarial review rounds and disposition;
- residual risks, follow-ups, or unauthorized external delivery steps.
