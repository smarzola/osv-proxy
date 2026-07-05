# Goal: Truthful Registry-Backed Check Command

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Make `osv-proxy check` answer the question users expect: "Would the proxy allow this package version under the configured policy and current upstream registry metadata?" The command must stop evaluating synthetic partial artifacts by default and instead fetch npm or PyPI metadata through the same adapter boundaries used by request handling.

Keep the implementation inside phase-one scope: naive OSV mode, redirect artifacts, no local malicious store, no metadata cache, no artifact proxying, and no S3/cachebox/MongoDB implementation.

## Repository Rules

- Implementation code is explicitly requested for this goal.
- Follow `AGENTS.md`: keep npm and PyPI specifics in adapter modules, keep the core policy model ecosystem-neutral, do not add an in-process metadata cache, and preserve the invariant that policy is checked during metadata generation and checked again during artifact serving.
- Do not add local malicious storage, MongoDB, cachebox, proxy streaming, S3, publishing support, broad scanning, or vulnerability severity policy.
- Do not revert unrelated user changes. You are not alone in this codebase.
- Prefer existing module boundaries: CLI orchestration in `src/cli.rs`, ecosystem metadata parsing in `src/npm.rs` and `src/pypi.rs`, policy in `src/policy.rs`, canonical artifacts in `src/artifact.rs`.
- If tests expose a product gap, fix the product rather than weakening the test.
- At the end of each milestone, run verification, mark the milestone done in this file, commit the completed milestone, and report the commit hash before continuing.

## Target State

By the end, `osv-proxy check <ecosystem:name@version> --config <path>` should:

- Load the configured upstream URLs, policy, allowlist/blocklist, and OSV settings from the supplied config path.
- For npm, fetch package metadata from `upstreams.npm.registry_url`, locate the requested version, build the canonical artifact from npm metadata including publish time, upstream tarball URL, filename, and hashes, then evaluate policy.
- For PyPI, fetch Simple JSON from `upstreams.pypi.simple_url`, locate files for the requested version, build canonical artifacts from file metadata including upload time, filename, upstream URL, and hashes, then evaluate policy.
- Print structured JSON that clearly reports the policy decision and enough artifact context for users to understand the result.
- Fail closed when upstream metadata is missing, malformed, or inconsistent with the requested version.
- Keep the existing synthetic/manual artifact evaluator only if it is renamed or explicitly marked as such, for example `eval` or `check --synthetic`. Do not let the default `check` path imply proxy-equivalent truth without registry metadata.

## Current State

- `src/cli.rs` handles `Command::Check` by parsing `ecosystem:name@version`, optionally accepting `--published-at`, constructing a partial synthetic `Artifact`, and calling `PolicyEngine::evaluate`.
- That path uses live OSV and the policy config, but it does not fetch npm/PyPI metadata and does not know real publish/upload time, upstream artifact URL, tarball/file basename, hashes, or whether the version exists upstream.
- The proxy adapters already know how to build artifacts for metadata filtering and artifact serving, but some helper functions are private and response-oriented rather than exposed for CLI evaluation.
- README currently says `check` evaluates one canonical package version and notes that it does not fetch publish time. That documentation will become inaccurate once `check` is registry-backed.

## Definition Of Done

The goal is complete only when:

1. `osv-proxy check npm:<name>@<version> --config <path>` evaluates the same npm artifact metadata the proxy would use for artifact serving.
2. `osv-proxy check pypi:<name>@<version> --config <path>` evaluates PyPI Simple JSON file metadata for that version.
3. Default `check` no longer needs `--published-at` for normal npm/PyPI registry-backed checks.
4. Missing upstream version/file metadata produces a clear non-zero failure or structured blocked/error response; it must not silently evaluate a synthetic artifact as if truthful.
5. Exact allowlist, blocklist, minimum-age, missing publish time, malicious hits, OSV errors, and `bypass_malicious` behavior are preserved.
6. Tests cover npm and PyPI registry-backed `check` behavior with mocked upstreams and mocked malicious checker; no live network is required for tests.
7. README and docs describe the truthful `check` command and, if retained, the synthetic/manual evaluation mode separately.
8. `cargo test` passes.
9. `cargo fmt --check` passes.
10. `cargo clippy --all-targets --all-features -- -D warnings` passes.
11. Milestone checkboxes in this file are marked `[x]` as work completes.
12. Each completed milestone has a focused commit.

## Milestone Checklist

When a milestone is complete:

1. Run the milestone's verification commands.
2. Update this checklist by changing the milestone from `[ ]` to `[x]`.
3. Add a short status note under that milestone with the date, exact commands run, and commit hash if available.
4. Commit the code, tests, docs, and checklist/status update with a focused commit message.
5. Report the commit hash in the goal-loop status before starting the next milestone.

- [x] Milestone 0: Baseline and command contract
- [x] Milestone 1: Adapter artifact lookup APIs
- [x] Milestone 2: Registry-backed CLI check orchestration
- [x] Milestone 3: Tests and docs for truthful check
- [ ] Milestone 4: Final regression and adversarial audit

## Milestone 0: Baseline and Command Contract

Problem:

- `check` currently has an ambiguous contract: it sounds proxy-equivalent but evaluates a manually supplied artifact shape.

Desired behavior:

- Lock the intended CLI contract before changing code.
- Decide whether to keep synthetic evaluation as a separate subcommand or option. Prefer a separate `eval` subcommand if it keeps `check` simple and truthful.

Acceptance criteria:

- Run current baseline verification commands and record results in this milestone's status note.
- Record the chosen CLI contract in this file's status note.
- Do not change implementation behavior in this milestone unless needed to make the contract explicit in tests.
- Milestone status is marked done in this file and committed.

Likely files:

- `docs/internal/goal-06-truthful-check-command.md`

Verification:

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note, 2026-07-06:

- Chosen CLI contract: default `check` is registry-backed and truthful for npm/PyPI; if synthetic/manual artifact evaluation is retained, it must live under a separate `eval` command and remain explicitly non-proxy-equivalent.
- Verification run:
  - `cargo test`: sandbox run failed in `server::tests::idle_connection_does_not_block_unrelated_request` with `Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }`; rerun outside sandbox passed, 81 library tests and 2 e2e tests.
  - `cargo fmt --check`: passed.
  - `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- Commit: pending.

## Milestone 1: Adapter Artifact Lookup APIs

Problem:

- The CLI needs canonical artifacts built from registry metadata, but the current npm/PyPI helpers are private and coupled to response filtering/redirect functions.

Desired behavior:

- Add small adapter-level APIs that fetch and build artifacts for a requested package identity without producing HTTP responses.
- Keep ecosystem-specific parsing inside `src/npm.rs` and `src/pypi.rs`.

Acceptance criteria:

- npm exposes an async function that, given config/upstream/package/version, returns the canonical npm artifact for that version or a clear `NpmError`.
- PyPI exposes an async function that, given config/upstream/project/version, returns one or more canonical PyPI artifacts for that version or a clear `PypiError`.
- For PyPI, decide and document how multiple files for one version are represented. The check command should fail if any installable file for the requested version would be blocked, or report per-file decisions clearly. Do not collapse multiple files into a misleading single artifact.
- Existing metadata filtering and artifact redirect behavior still use the same parsing rules or the new shared helpers.
- No live network calls are introduced in tests.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/npm.rs`
- `src/pypi.rs`
- `src/artifact.rs`

Verification:

```sh
cargo test npm
cargo test pypi
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note, 2026-07-06:

- Added adapter lookup contract: npm exposes one registry-derived tarball artifact for a requested package version; PyPI exposes all registry-derived files for a requested project version and callers must evaluate/report each file rather than collapsing them into one artifact.
- Verification run:
  - `cargo test npm`: sandbox run passed 24 matching unit/server tests, then selected `npm_install_uses_proxy_for_allowed_and_blocked_versions` and failed with `Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }`; rerun outside sandbox passed all 24 matching unit/server tests plus the npm e2e test.
  - `cargo test pypi`: passed, 23 matching tests.
  - `cargo fmt --check`: passed after `cargo fmt`.
- Commit: pending.

## Milestone 2: Registry-Backed CLI Check Orchestration

Problem:

- `src/cli.rs` currently constructs a partial artifact and directly calls policy. That bypasses the proxy's registry-backed truth source.

Desired behavior:

- Default `check` loads config, routes by ecosystem, fetches registry metadata through adapter providers, evaluates policy, and prints a structured result.
- Retain synthetic evaluation only under a name that cannot be mistaken for proxy-equivalent behavior, or remove it if unused.

Acceptance criteria:

- `check npm:demo@1.0.0 --config <path>` uses npm metadata lookup and does not require `--published-at`.
- `check pypi:demo@1.0.0 --config <path>` uses PyPI Simple JSON lookup and does not require `--published-at`.
- The command output includes the package identity, allowed/blocked decision, and registry-derived artifact context. For PyPI with multiple files, output per-file decisions or a clear aggregate with per-file details.
- Exit code remains useful: success only when the requested package version would be allowed by the proxy; non-zero when blocked or when registry metadata cannot support a truthful answer.
- If a synthetic/manual evaluator is retained, tests and help text make the difference explicit.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/cli.rs`
- `src/npm.rs`
- `src/pypi.rs`
- `src/policy.rs`
- `src/artifact.rs`

Verification:

```sh
cargo test cli
cargo test npm
cargo test pypi
cargo test policy
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note, 2026-07-06:

- Implemented default `check` as registry-backed orchestration: parse package identity without constructing a partial artifact, fetch npm/PyPI metadata through adapter lookup APIs, evaluate each registry-derived artifact, print aggregate JSON with per-artifact decisions, and return non-zero for blocked results.
- Retained manual artifact evaluation only as `eval`, with synthetic mode in output and command help.
- PyPI check evaluates every file for the requested version and reports an aggregate allow only when all file decisions allow.
- Adapted to the current concurrent config shape by using `policy.osv.api_url`, `policy.osv.on_error`, and preserving `policy.osv.only_mal_ids`.
- Verification run:
  - `cargo test cli`: passed, 7 matching tests.
  - `cargo test npm`: sandbox run passed 25 matching unit/server tests, then selected `npm_install_uses_proxy_for_allowed_and_blocked_versions` and failed with `Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }`; rerun outside sandbox passed all 25 matching unit/server tests plus the npm e2e test.
  - `cargo test pypi`: passed, 24 matching tests.
  - `cargo test policy`: passed, 17 matching tests.
  - `cargo fmt --check`: passed.
- Commit: pending.

## Milestone 3: Tests and Docs for Truthful Check

Problem:

- Users need to know that `check` now performs registry-backed proxy-equivalent evaluation, and tests need to prevent regression to synthetic checks.

Desired behavior:

- Tests prove `check` uses adapter metadata, not only supplied identity and OSV.
- Docs describe correct examples and failure modes.

Acceptance criteria:

- Add tests where npm/PyPI `check` allows an old version using publish/upload time from mocked registry metadata without `--published-at`.
- Add tests where npm/PyPI `check` blocks too-new versions using registry metadata.
- Add tests where missing upstream version/file metadata fails clearly.
- Add tests where manual blocklist and allowlist are respected through registry-backed check.
- Update README's `Check a Package` section and relevant docs to remove the old warning that default `check` does not fetch publish time.
- If synthetic evaluation remains, document it separately and make its limitations explicit.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/cli.rs`
- `src/npm.rs`
- `src/pypi.rs`
- `README.md`
- `docs/client-configuration.md`
- `docs/policy.md`

Verification:

```sh
cargo test check
cargo test cli
cargo test
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note, 2026-07-06:

- Added mocked registry-backed `check` tests for npm and PyPI old-version allows, npm too-new blocking, PyPI per-file blocking, missing npm/PyPI upstream versions, manual blocklist, and allowlist age/malicious bypass behavior. No live npm, PyPI, or OSV network is used.
- Updated README, configuration docs, and policy docs so `check` is described as registry-backed and `eval` is described as synthetic/manual. Updated example configs for the current `policy.osv` shape and restored `examples/phase1/osv-proxy.yaml` for final validation.
- Verification run:
  - `cargo test check`: passed, 13 matching tests.
  - `cargo test cli`: passed, 13 matching tests.
  - `cargo test`: sandbox run passed 89 library tests then failed `server::tests::idle_connection_does_not_block_unrelated_request` with `Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }`; rerun outside sandbox passed 90 library tests and 2 e2e tests.
- Commit: pending.

## Milestone 4: Final Regression and Adversarial Audit

Problem:

- The CLI check path touches policy, adapters, docs, and user-facing command semantics. It must not break proxy behavior or phase-one scope.

Desired behavior:

- Full regression passes and an adversarial audit confirms `check` is truthful by default.

Acceptance criteria:

- Full test, format, and clippy verification pass.
- `cargo run -- config validate --config examples/phase1/osv-proxy.yaml` passes.
- Review `src/cli.rs` to confirm default `check` does not construct a partial synthetic artifact for npm/PyPI.
- Review npm/PyPI adapter paths to confirm artifact construction is shared or behavior-equivalent with proxy artifact serving.
- Scope audit confirms no forbidden storage/cache/proxy features were introduced.
- Milestone status is marked done in this file and committed.

Likely files:

- `docs/internal/goal-06-truthful-check-command.md`
- Any files touched by prior milestones

Verification:

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/phase1/osv-proxy.yaml
rg -n "parse_identity\\(&package, published_at\\)|published_at: Option<DateTime<Utc>>|synthetic|eval" src README.md docs
rg -n "mongodb|cachebox|S3|proxy_cache_s3|memory cache|HashMap.*cache|artifact cache|proxy streaming" src examples docs
git diff --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Final Response Required

When complete, report:

- Target state achieved or not achieved.
- CLI contract chosen for registry-backed and synthetic/manual evaluation.
- Commits made, with hashes.
- Files changed.
- Exact verification commands run and results.
- Any intentionally deferred product scope.
- Known residual risks or follow-up issues.
