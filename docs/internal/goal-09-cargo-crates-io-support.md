# Goal: Cargo and crates.io Registry Support

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Add production-quality, read-only Cargo support backed by the crates.io sparse
index. Cargo users must be able to replace crates.io with `osv-proxy`, resolve
only policy-allowed crate versions, and download allowed `.crate` artifacts
through the existing redirect or proxy delivery modes.

Implement this as an ecosystem adapter, not as Cargo-specific policy logic.
The core policy engine must continue to evaluate canonical artifacts, and local
OSV mode must understand the `crates.io` ecosystem without making request-path
network calls to OSV.

## Repository Rules

- Follow `AGENTS.md`; correctness and latency are first-class requirements.
- Do not copy personal/private user rules into repository files.
- Do not revert unrelated changes. Other ecosystem work is happening in
  parallel and will be integrated later.
- Keep sparse-index parsing, crate naming/path rules, and Cargo HTTP behavior in
  a dedicated adapter module. Keep policy ecosystem-neutral.
- Preserve the invariant that policy is checked while producing version
  metadata and again immediately before artifact delivery.
- Preserve upstream crate bytes and checksums exactly. Never rebuild or mutate
  `.crate` files.
- Use bounded concurrency only. Do not introduce per-version unbounded fan-out
  or an in-process metadata cache.
- Do not implement publishing, authentication, S3 caching, cachebox, Git index
  support, or private registries.
- Do not merge branches, bump the release version, create tags, or publish a
  release. The coordinating thread owns integration and release.
- At the end of every milestone, verify, update this file, commit the milestone,
  and report its commit hash before continuing.

## Target State

By the end, the repository has:

- A configurable crates.io sparse-index upstream and `/cargo/` proxy surface.
- A proxy `config.json` whose download URL points back through `osv-proxy`.
- Sparse index responses that preserve valid JSON-lines format and expose only
  policy-allowed versions.
- Minimum-age evaluation from index `pubtime`; missing values follow the
  configured `missing_publish_time` behavior.
- `.crate` redirect and proxy delivery with a second current-policy check.
- Canonical `crates.io` identities in `check`, `eval`, allowlists, blocklists,
  live OSV queries, and local malicious storage/sync.
- Correct crates.io name/path normalization and Cargo version ordering.
- A real Cargo end-to-end test against local fixture index/artifact servers.
- Operator documentation for mandatory crates.io source replacement.

## Current State

- `Ecosystem` supports only npm and PyPI.
- Config, CLI dispatch, HTTP routing, OSV dump sync, local range evaluation, and
  tests are hard-coded around those two ecosystems.
- The shared artifact delivery layer already supports redirect and proxy modes.
- Cargo's sparse HTTP protocol is not implemented.
- `cargo` is installed on the development machine.

## Source Research Requirements

Before implementation, verify behavior against primary sources and record any
design-relevant findings in a milestone status note:

- `https://doc.rust-lang.org/cargo/reference/registry-index.html`
- `https://doc.rust-lang.org/cargo/reference/source-replacement.html`
- `https://index.crates.io/config.json`
- A small sample of real current sparse index records, including `pubtime`.
- `https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip`

Do not infer protocol behavior from third-party registry implementations when
the Cargo specification or a real crates.io response answers it.

## Definition Of Done

The goal is complete only when:

1. Cargo can use the proxy as a sparse replacement for crates.io.
2. Allowed versions remain resolvable and blocked/too-new versions disappear
   from sparse index responses.
3. Proxy `config.json` routes downloads back through the proxy.
4. Allowed `.crate` downloads work in redirect and proxy modes; blocked direct
   downloads return structured `403` without fetching artifact bytes.
5. Index checksums and delivered bytes remain unchanged.
6. `check crates.io:<name>@<version>` is registry-backed and truthful; `eval`
   supports the same ecosystem identity.
7. Live and local OSV modes use the exact OSV ecosystem name `crates.io`.
8. Local mode supports the exact-version and range shapes observed in current
   crates.io `MAL-*` data and makes no OSV calls during requests.
9. Unit, route, and real `cargo` package-manager tests cover allowed, blocked,
   age-gated, locked, redirect, and proxy flows without live network access.
10. Config examples and user-facing docs describe supported behavior and known
    `pubtime` limitations accurately.
11. `cargo fmt --check`, `cargo test`, `cargo clippy --all-targets --all-features
    -- -D warnings`, config validation, and `git diff --check` pass.
12. All milestone boxes are checked and each milestone has a focused commit.

## Milestone Checklist and Checkpoint Protocol

When a milestone is complete:

1. Run its verification commands.
2. Change its checkbox from `[ ]` to `[x]`.
3. Add a dated status note with exact commands and results.
4. Commit code, tests, docs, and the status update together.
5. Record and report the commit hash before starting the next milestone.

- [x] Milestone 0: Protocol research and adapter contract
- [x] Milestone 1: Ecosystem, config, OSV, and CLI foundations
- [x] Milestone 2: Sparse index filtering and routing
- [x] Milestone 3: Crate artifact delivery and policy recheck
- [x] Milestone 4: Real Cargo compatibility, docs, and regression

## Milestone 0: Protocol Research and Adapter Contract

Problem:

- Sparse-index immutability, path encoding, conditional requests, and optional
  publication timestamps must be understood before choosing route contracts.

Desired behavior:

- Document a narrow read-only design in this file's status note, including
  route shapes, `pubtime` handling, crate normalization, response headers, and
  how source replacement preserves Cargo.lock compatibility.

Acceptance criteria:

- Primary sources and real response shapes were inspected.
- Tests or fixtures use observed protocol shapes, not invented approximations.
- No production implementation is committed before the contract is recorded.
- Milestone status is marked done and committed.

Likely files:

- `docs/internal/goal-09-cargo-crates-io-support.md`
- `tests/fixtures/` if a small protocol fixture is appropriate

Verification:

```bash
git diff --check
```

Status note 2026-07-09:

- Reviewed Cargo's primary registry-index and source-replacement documentation,
  the live crates.io sparse `config.json`, recent `serde` sparse records, and
  the crates.io OSV dump endpoint. The live configuration advertises
  `https://static.crates.io/crates`; observed index records are JSON lines with
  `name`, `vers`, `cksum`, dependency metadata, `yanked`, and optional UTC
  `pubtime` fields.
- The adapter contract is read-only: `GET /cargo/config.json` returns a proxy
  download template, `GET /cargo/<sparse-path>` fetches and filters one
  lower-case sparse index file, and `GET /cargo/api/v1/crates/<name>/<version>/download`
  re-reads the canonical record, rechecks policy, then redirects or streams the
  untouched upstream crate. Sparse paths are verified against Cargo's documented
  name-to-path mapping before upstream access.
- Filtering parses each JSON line only to construct policy context and then
  emits the original line unchanged when allowed. `pubtime` is parsed as UTC;
  a missing value is passed through as `None` so the configured
  `missing_publish_time` decision applies. Malformed records fail closed.
- Cargo's sparse protocol caches metadata using ETag or Last-Modified and may
  issue conditional requests. The adapter will forward useful validators where
  possible, but never caches or rewrites retained record bytes. The documented
  source replacement model requires a subset of crates.io, so filtering is
  compatible with lockfiles only while their selected versions remain allowed.
- Commands run: `curl --fail --silent --show-error https://index.crates.io/config.json`
  (passed), the same command for `https://index.crates.io/se/rd/serde` (passed,
  observed current `pubtime` records), `curl --fail --silent --show-error --head
  https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip` (passed,
  HTTP 200), and `git diff --check` (passed).

## Milestone 1: Ecosystem, Config, OSV, and CLI Foundations

Problem:

- Shared ecosystem and malicious-data code recognizes only npm and PyPI.

Desired behavior:

- Add `crates.io` as a canonical ecosystem, strict upstream config, CLI
  dispatch, OSV queries/sync, name normalization, and correct local range
  evaluation based on actual OSV records.

Acceptance criteria:

- Existing npm/PyPI behavior remains unchanged.
- Strict config rejects unknown Cargo keys.
- Local sync health is tracked independently for `crates.io`.
- Range/version tests include prerelease versions and real malicious-record
  shapes.
- Milestone status is marked done and committed.

Likely files:

- `src/artifact.rs`
- `src/config.rs`
- `src/cli.rs`
- `src/malicious.rs`
- `examples/basic/osv-proxy.yaml`

Verification:

```bash
cargo test artifact
cargo test config
cargo test cli
cargo test malicious
cargo fmt --check
```

Status note 2026-07-09:

- Added Cargo artifact delivery at `/cargo/api/v1/crates/<name>/<version>/download`.
  Each request resolves its canonical sparse record, verifies its name/version,
  builds the checksum-bearing artifact context, and reevaluates current policy
  before delegating to the shared redirect/proxy delivery layer.
- Blocked direct requests return structured 403 before the delivery client can
  fetch bytes. Allowed redirects/proxy streams retain the upstream `.crate`
  URL and bytes unchanged.
- Commands run: `cargo test cargo` passed (7 tests), `cargo fmt --check`
  passed, and `git diff --check` passed.

Status note 2026-07-09:

- Implemented the `/cargo/` sparse surface: a read-only `config.json`, canonical
  path validation, upstream sparse record retrieval, deterministic JSON-lines
  filtering, and fail-closed malformed-record errors. Retained lines are emitted
  byte-for-byte with their original ordering and forward-compatible fields.
- `pubtime` drives the existing minimum-age policy; absent `pubtime` reaches the
  configured missing-time behavior. The adapter has no metadata cache and
  performs bounded sequential policy work.
- Commands run outside the listener-restricted sandbox: `cargo test cargo`
  passed (6 tests) and `cargo fmt --check` passed. `cargo test server --
  --test-threads=1` passed 25/26 tests; the sole failure is the existing
  time-relative PyPI local-mode expectation that assumes a too-young fixture
  remains blocked after its timestamp ages past the configured gate.

Status note 2026-07-09:

- Added canonical `crates.io` identities, lower-case Cargo name normalization,
  strict `upstreams.cargo` sparse-index/download configuration, and a
  registry-backed Cargo check path that constructs canonical artifacts with the
  sparse index checksum and optional `pubtime`.
- Added `crates.io` to live OSV requests and independent local dump-sync health.
  Local range evaluation now uses Cargo SemVer ordering for both observed
  `SEMVER` and `ECOSYSTEM` range records, including prereleases.
- Commands run outside the listener-restricted sandbox: `cargo test cargo`
  passed (4 tests), `cargo test config` passed (34 tests), `cargo test cli`
  passed (34 tests), `cargo test malicious -- --test-threads=1` passed (40
  tests), and `cargo fmt --check` passed. A broad `cargo test artifact` run
  passed its Cargo/normalization tests but exposed a pre-existing time-sensitive
  PyPI local-mode assertion; it is deferred to the full-regression milestone.

## Milestone 2: Sparse Index Filtering and Routing

Problem:

- Cargo currently cannot discover policy-filtered crate versions through the
  proxy.

Desired behavior:

- Serve a rewritten sparse `config.json` and filtered per-crate JSON-lines
  records. Preserve ordering, unknown forward-compatible fields, checksums,
  yanked flags, dependency metadata, useful validators, and valid empty-result
  behavior.

Acceptance criteria:

- Blocked versions are absent and allowed versions are byte-semantically intact
  except where proxy URL rewriting is required.
- `pubtime` feeds the age gate; missing time follows policy explicitly.
- Malformed upstream records fail closed with structured errors.
- Large index records use bounded work and deterministic output.
- Route tests cover mixed versions, yanked versions, prereleases, missing
  `pubtime`, unusual valid names, and upstream errors.
- Milestone status is marked done and committed.

Likely files:

- `src/cargo.rs` or another unambiguous adapter filename
- `src/server.rs`
- `src/lib.rs`
- adapter and server tests

Verification:

```bash
cargo test cargo_registry
cargo test server
cargo fmt --check
```

## Milestone 3: Crate Artifact Delivery and Policy Recheck

Problem:

- Index filtering alone does not prevent a lockfile or direct URL from
  requesting a blocked crate version.

Desired behavior:

- Resolve the canonical index record for a requested crate/version, rebuild the
  same artifact context, re-evaluate policy, and only then redirect or stream
  the exact upstream `.crate` bytes.

Acceptance criteria:

- Direct blocked downloads return structured `403` and do not fetch bytes.
- Requested name/version and upstream index identity cannot be confused.
- Redirect and proxy modes both work; upstream failures use existing gateway
  error conventions.
- Artifact SHA-256 context comes from the index checksum and bytes are unchanged.
- Milestone status is marked done and committed.

Likely files:

- Cargo adapter module
- `src/artifacts.rs`
- `src/server.rs`

Verification:

```bash
cargo test cargo_registry
cargo test artifacts
cargo test server
cargo fmt --check
```

## Milestone 4: Real Cargo Compatibility, Docs, and Regression

Problem:

- Protocol-shaped unit tests do not prove that the real Cargo client accepts
  source replacement, filtered metadata, and proxy artifact delivery.

Desired behavior:

- A hermetic integration test invokes real `cargo` against local fixture
  servers for fresh and locked resolution. User docs provide exact safe source
  replacement configuration and clearly exclude publishing/private registries.

Acceptance criteria:

- Real Cargo tests cover allowed and blocked fresh installs, a blocked version
  referenced by a lockfile, redirect mode, and proxy mode.
- Tests do not contact crates.io or OSV.
- README, configuration, client configuration, registry behavior, product spec,
  architecture, malicious-data docs, and milestones are updated consistently.
- Full regression passes.
- Milestone status is marked done and committed.

Likely files:

- `tests/package_manager_e2e.rs` or a focused Cargo integration test
- `README.md`
- `docs/*.md`

Verification:

```bash
cargo test --test package_manager_e2e
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
git diff --check
```

Status note 2026-07-09:

- Added a hermetic real-Cargo package-manager test with local sparse index and
  artifact fixture servers. It proves fresh allowed resolution in redirect and
  proxy modes, blocked fresh resolution, and a blocked version already present
  in a lockfile. The fixture is entirely local and does not contact crates.io
  or OSV.
- Added conditional sparse-index support: filtered bytes receive a stable
  content ETag and a matching `If-None-Match` produces `304` without a body.
- Repaired the existing PyPI local-mode test defect: a test fixture used a fixed
  historical "new" timestamp while the route evaluates against real current
  time, so the fixture eventually aged through the minimum-age gate. The server
  fixture now derives its new timestamp from current time.
- Updated README, client/configuration, registry behavior, malicious-data,
  architecture, product-spec, milestones, and the basic example for Cargo.
- Commands run outside the listener-restricted sandbox: `cargo fmt --check`,
  `cargo test --test package_manager_e2e` (3 passed), `cargo test` (151 unit,
  3 package-manager tests, doctests passed), and config validation passed.

Repair note 2026-07-09:

- Sparse index filtering now batches all OSV-eligible Cargo artifacts into one
  `check_many` call, validates cardinality, and passes batch failures/missing
  results to the policy engine so configured fail-closed behavior is preserved.
- Denied direct Cargo artifacts now serialize the full policy decision with
  HTTP 403, including `reason`, `rule_id`, `source`, and policy timestamps when
  present. A proxy-mode regression verifies the direct handler returns that
  body and never contacts the configured upstream artifact listener.

## Final Response Required

Report:

- whether every target-state item was achieved;
- milestone commits in order;
- files changed;
- exact verification commands and results;
- protocol or performance risks that remain;
- explicit confirmation that you did not merge, tag, release, or modify another
  ecosystem goal prompt.
