# Goal: Concurrency and Policy Hardening

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Harden the phase-one implementation after adversarial review. Keep the product scope narrow: deterministic package policy enforcement for npm and PyPI, naive OSV mode, redirect artifacts, no local storage, and no metadata cache.

This goal fixes the two highest-risk runtime problems with Tokio-based concurrency and nonblocking bounded request handling, then closes the remaining policy, configuration, and client-compatibility gaps found in review.

## Repository Rules

- Implementation code is explicitly requested for this goal.
- Follow `AGENTS.md`: keep npm and PyPI specifics in adapter modules, keep the core policy model ecosystem-neutral, do not add an in-process metadata cache, and preserve the invariant that policy is checked during metadata generation and checked again during artifact serving.
- Do not add local malicious storage, MongoDB, cachebox, proxy streaming, S3, publishing support, broad scanning, or vulnerability severity policy.
- Do not revert unrelated user changes. Work with the current tree.
- Prefer the repo's existing module boundaries and focused unit tests.
- If tests expose a real product gap, fix the product rather than weakening the test.
- At the end of each milestone, run verification, mark the milestone done in this file, commit the completed milestone, and report the commit hash before continuing.

## Target State

By the end, `osv-proxy` should:

- Run on a Tokio HTTP server that can serve multiple concurrent requests and cannot be held hostage by one idle or slow client.
- Use nonblocking upstream npm, PyPI, and OSV clients with explicit request timeouts.
- Avoid serial one-request-per-version OSV behavior during metadata filtering by using a batched or bounded-concurrency malicious check path.
- Reject npm artifact URLs unless the requested tarball basename exactly matches the version's upstream metadata tarball basename.
- Reject unknown YAML config fields and invalid oversize durations during config validation.
- Serve or rewrite the PyPI Simple root in a way that keeps clients on supported `/pypi/simple/...` proxy routes.
- Keep all existing phase-one behavior passing: metadata filtering, second artifact policy checks, redirect artifact mode, and unsupported-mode validation.

## Current State

- `src/server.rs` uses `std::net::TcpListener` and handles `listener.incoming()` serially.
- `src/server.rs` reads directly from a blocking `TcpStream` without a read timeout.
- `src/npm.rs`, `src/pypi.rs`, and `src/malicious.rs` use `reqwest::blocking::Client`.
- Metadata filtering evaluates policy one item at a time, which means one synchronous OSV call per npm version or PyPI file in naive mode.
- npm artifact serving infers the version from the requested tarball name but does not verify that the requested basename is the version's real upstream tarball basename.
- Config structs use `#[serde(default)]` but not `deny_unknown_fields`, so policy typos can validate with defaults.
- Very large `policy.minimum_age` values can pass config load and later panic in policy evaluation when converted to `chrono::Duration`.
- PyPI Simple root currently passes upstream root HTML through unchanged, which can expose upstream `/simple/...` links instead of proxy `/pypi/simple/...` links.

## Definition Of Done

The goal is complete only when:

1. `cargo test` passes.
2. `cargo fmt --check` passes.
3. `cargo clippy --all-targets --all-features -- -D warnings` passes.
4. Tests prove concurrent/slow connections no longer block unrelated requests.
5. Tests prove metadata filtering does not call the malicious checker once per package file/version when a batch path is available.
6. Tests prove npm artifact basename mismatches return 404 and do not redirect.
7. Tests prove unknown config keys and oversize durations fail validation.
8. Tests prove PyPI root output keeps links on supported proxy routes or the route is no longer advertised as pass-through.
9. Milestone checkboxes in this file are marked `[x]` as work completes.
10. Each completed milestone has a focused commit.
11. Final verification commands pass or unrelated failures are documented with evidence.

## Milestone Checklist

When a milestone is complete:

1. Run the milestone's verification commands.
2. Update this checklist by changing the milestone from `[ ]` to `[x]`.
3. Add a short status note under that milestone with the date, exact commands run, and commit hash if available.
4. Commit the code, tests, docs, and checklist/status update with a focused commit message.
5. Report the commit hash in the goal-loop status before starting the next milestone.

- [x] Milestone 0: Baseline and async design lock
- [x] Milestone 1: Tokio HTTP server and request timeouts
- [x] Milestone 2: Nonblocking upstream clients and bounded malicious checks
- [x] Milestone 3: npm artifact basename enforcement
- [x] Milestone 4: Strict config validation
- [x] Milestone 5: PyPI Simple root compatibility
- [x] Milestone 6: Final regression and docs audit

## Milestone 0: Baseline and Async Design Lock

Status note - 2026-07-05:

- Baseline verification:
  - `cargo test` failed in the sandbox before product assertions because `tests/package_manager_e2e.rs:371` could not bind `127.0.0.1:0`: `Operation not permitted`.
  - `cargo test` passed outside the sandbox: 63 library tests, 0 main tests, 2 package-manager integration tests, and 0 doc tests.
  - `cargo fmt --check` passed.
  - `cargo clippy --all-targets --all-features -- -D warnings` passed.
- Async design lock:
  - `serve --config <path>` will load config through the existing CLI path, then run a Tokio runtime from `main` and serve with Axum on a Tokio listener.
  - Routing will move behind an Axum `Router`/handler layer that preserves the current route parsing and `RegistryResponse` behavior while letting tests call routes without binding ports through Tower `ServiceExt::oneshot`.
  - Request handling will stay GET-only. Non-GET methods continue to return 405 from the routing layer.
  - Tower/Tower HTTP will be used for bounded request behavior where it fits the GET-only proxy: request body size will be limited and per-request timeout will be applied at the service layer.
  - npm, PyPI, and OSV clients will become nonblocking `reqwest::Client` instances with explicit connect/request timeouts in Milestone 2. Adapter traits will remain injectable so tests can use fake providers/checkers without live npm, PyPI, or OSV calls.
  - Server concurrency will be tested with a local bound listener by opening an idle or slow TCP connection, then proving a normal HTTP request still completes on another connection.
  - Metadata filtering will use a request-local batch or bounded-concurrency malicious-check path in Milestone 2. No in-process metadata cache, local malicious store, proxy streaming, S3, MongoDB, or cachebox integration will be added.
- Commit: `ca6815a`.

Problem:

- The current code has strong unit coverage but no explicit tests around the reviewed failure modes.
- The async migration affects shared request routing and external service boundaries, so the intended shape must be clear before editing.

Desired behavior:

- Establish the baseline and write down the concrete implementation plan in this file before code changes.
- Use the selected async stack: Tokio runtime, Axum for HTTP routing/server behavior, Tower or Tower HTTP for timeouts/request limits where useful, and nonblocking `reqwest::Client`.
- Keep adapter traits testable without live npm, PyPI, or OSV calls.

Acceptance criteria:

- Run the current baseline verification commands and record results in this milestone's status note.
- Record the Axum/Tokio implementation plan in the status note, including how Tower timeout or request-limit layers will be applied.
- Identify how route tests will call request routing without binding live ports, and how server concurrency will be tested with a local bound listener.
- Milestone status is marked done in this file and committed.

Likely files:

- `docs/internal/goal-05-concurrency-policy-hardening.md`

Verification:

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 1: Tokio HTTP Server and Request Timeouts

Status note - 2026-07-05:

- Implemented `serve --config <path>` on a Tokio runtime with an Axum catch-all router, a Tokio listener, an 8 KiB default request body limit, and a 15 second Tower HTTP request timeout.
- Preserved the existing deterministic route/policy behavior by keeping the route functions injectable for tests and adapting the live HTTP handler around them.
- Added route verification through `Router::oneshot` without binding a live port for the non-GET 405 path.
- Added a local-listener concurrency test that holds one idle TCP connection open and proves a second normal request returns `404 Not Found` instead of blocking behind the idle client.
- Verification:
  - `cargo test server` failed in the sandbox only at `TcpListener::bind("127.0.0.1:0")` with `Operation not permitted`.
  - `cargo test server` passed outside the sandbox: 17 server-filtered tests passed.
  - `cargo test e2e` passed outside the sandbox: 4 e2e-filtered library tests passed.
  - `cargo fmt --check` passed.
- Commit: `3b7781f`.

Problem:

- One idle client can block the entire server because requests are accepted and handled serially with blocking reads.

Desired behavior:

- Replace the hand-rolled blocking TCP server with a Tokio-based HTTP server.
- Each request is handled independently so one idle or slow connection cannot block unrelated clients.
- Request body/read behavior has sane limits and timeouts for this proxy's GET-only route set.

Acceptance criteria:

- `serve --config <path>` starts the async server and uses Tokio runtime wiring.
- Existing route-level tests continue to pass after adapting async signatures where needed.
- Add a test that opens an idle or deliberately slow connection and proves a normal request still completes.
- Non-GET methods still return 405.
- The implementation does not add metadata caching, proxy streaming, S3, or local malicious storage.
- Milestone status is marked done in this file and committed.

Likely files:

- `Cargo.toml`
- `src/main.rs`
- `src/cli.rs`
- `src/server.rs`
- `src/response.rs`

Verification:

```sh
cargo test server
cargo test e2e
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 2: Nonblocking Upstream Clients and Bounded Malicious Checks

Status note - 2026-07-05:

- Converted live npm, PyPI, and OSV clients from `reqwest::blocking::Client` to nonblocking `reqwest::Client` with 5 second connect timeouts and 10 second request timeouts.
- Added an async `MaliciousChecker::check_many` path. The OSV client uses `/v1/querybatch` for metadata filtering and keeps `/v1/query` for direct artifact serving.
- Metadata filtering for npm versions and PyPI files now performs one request-local batch malicious check, then evaluates policy with the returned per-artifact results. This does not add metadata caching or persistent malicious storage.
- Direct npm and PyPI artifact serving still performs a single second policy check for the requested artifact.
- Updated tests with fake batch-aware checkers that assert metadata filtering uses one batch call and zero single malicious calls when the batch path is available.
- Verification:
  - `cargo test malicious` passed: 8 filtered tests passed.
  - `cargo test policy` passed: 14 filtered tests passed.
  - `cargo test npm` failed in the sandbox only at the package-manager e2e loopback bind with `Operation not permitted`; `cargo test npm` passed outside the sandbox with 17 library-filtered tests and 1 package-manager integration test.
  - `cargo test pypi` passed: 18 filtered tests passed.
  - `cargo test e2e` passed outside the sandbox: 4 e2e-filtered library tests passed.
- Commit: `54d7f39`.

Problem:

- Metadata filtering currently performs one synchronous OSV request per npm version or PyPI file. Large package metadata can make installs slow and easy to exhaust.

Desired behavior:

- Convert npm, PyPI, and OSV HTTP clients to nonblocking `reqwest::Client` with explicit connect/request timeouts.
- Add a batch-aware malicious-check interface for metadata filtering. Prefer OSV's batch query endpoint if the current API supports it; otherwise use bounded async concurrency with a strict limit.
- Preserve single-artifact malicious checks for direct artifact serving.
- Do not add an in-process metadata cache. Batching or bounded concurrency is request-local only.

Acceptance criteria:

- Metadata adapters evaluate malicious status through a request-local batch or bounded-concurrency path instead of unbounded serial blocking calls.
- Tests use fake malicious checkers and prove metadata filtering no longer calls the checker once per item when the batch path is available.
- OSV/upstream HTTP clients have configured timeouts, and timeout behavior respects `policy.malicious.on_osv_error`.
- Existing malicious-policy behavior remains: only `MAL-*` blocks by default, non-`MAL` advisories are ignored unless configured otherwise, and `bypass_malicious=true` skips malicious checks for the exact allowlisted version.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/malicious.rs`
- `src/policy.rs`
- `src/npm.rs`
- `src/pypi.rs`
- `src/server.rs`
- `Cargo.toml`

Verification:

```sh
cargo test malicious
cargo test policy
cargo test npm
cargo test pypi
cargo test e2e
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 3: npm Artifact Basename Enforcement

Status note - 2026-07-05:

- Enforced npm artifact basename matching during direct artifact serving: the requested tarball basename must exactly match the upstream metadata `dist.tarball` basename for the inferred version.
- Basename mismatches now return `404` through the npm error response path and do not perform the second malicious/policy check or return a redirect.
- Added unscoped and scoped npm tests for wrong basenames such as `anything-1.0.0.tgz` and `anything-7.24.0.tgz`, and preserved the existing correct-basename redirect test.
- Updated registry behavior docs to describe the basename guard.
- Verification:
  - `cargo test npm` passed outside the sandbox: 19 library-filtered tests and 1 package-manager integration test passed.
  - `cargo test e2e_npm` passed: 2 e2e npm route tests passed.
  - `cargo test server` passed outside the sandbox: 17 server-filtered tests passed.
- Commit: `dc74bc3`.

Problem:

- The npm artifact route infers a version from the requested tarball filename and then redirects to that version's upstream `dist.tarball`, without proving the requested filename is actually the version's tarball.

Desired behavior:

- Direct npm artifact routes only redirect when the requested tarball basename exactly matches the upstream metadata tarball basename for the inferred version.
- Mismatched basenames return 404, not a redirect and not a policy decision for a different artifact.

Acceptance criteria:

- Add tests for unscoped and scoped npm packages where `anything-<version>.tgz` or another wrong basename returns 404.
- Add tests that the correct basename still redirects after the second policy check.
- Do not loosen version inference for metadata-generated proxy URLs; metadata rewrite should keep using the upstream tarball basename when present.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/npm.rs`
- `src/server.rs`
- `docs/registry-behavior.md`

Verification:

```sh
cargo test npm
cargo test e2e_npm
cargo test server
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 4: Strict Config Validation

Status note - 2026-07-05:

- Added Serde unknown-field rejection for supported config structs: top-level config, `server`, `upstreams`, `upstreams.npm`, `upstreams.pypi`, `policy`, `policy.malicious`, `allowlist`, `blocklist`, `metadata_cache`, and `artifacts`.
- Added config-load validation that `policy.minimum_age` can be converted to `chrono::Duration`, preventing policy evaluation panics from oversize durations.
- Added tests for unknown top-level keys and nested unknown keys under `policy`, `policy.malicious`, `server`, `upstreams.npm`, `upstreams.pypi`, `metadata_cache`, and `artifacts`, plus an oversize `minimum_age` test.
- Updated configuration docs to state that unknown YAML keys fail validation and `minimum_age` must fit policy evaluation.
- Verification:
  - `cargo test config` passed: 19 filtered tests passed.
  - `cargo run -- config validate --config examples/phase1/osv-proxy.yaml` passed and printed `configuration is valid for phase one`.
  - `cargo test policy` passed: 16 filtered tests passed.
- Commit: `a940cb7`.

Problem:

- Policy typos can validate silently because config structs default missing fields and allow unknown fields.
- Oversize duration values can pass config load and panic later when policy evaluation converts to `chrono::Duration`.

Desired behavior:

- Unknown YAML fields are rejected clearly across supported config structs.
- `policy.minimum_age` is validated during config load so request handling cannot panic because of duration conversion.
- Supported example configs continue to validate.

Acceptance criteria:

- Add `deny_unknown_fields` or equivalent explicit unknown-field rejection for all supported config structs.
- Add tests for unknown top-level keys and nested unknown keys under `policy`, `policy.malicious`, `server`, `upstreams.npm`, `upstreams.pypi`, `metadata_cache`, and `artifacts`.
- Add validation for `minimum_age` compatibility with policy evaluation and a test for an oversize duration.
- Existing unsupported-mode validation tests continue to pass.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/config.rs`
- `examples/phase1/osv-proxy.yaml`
- `docs/configuration.md`

Verification:

```sh
cargo test config
cargo run -- config validate --config examples/phase1/osv-proxy.yaml
cargo test policy
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 5: PyPI Simple Root Compatibility

Status note - 2026-07-05:

- Changed `GET /pypi/simple/` from upstream pass-through to a minimal rendered root page whose project links point at `{server.public_base_url}/pypi/simple/{project}/`.
- Root rendering extracts project links from upstream absolute `/simple/...` paths, relative project links, and full upstream Simple URLs.
- Added a root test covering absolute, relative, and full upstream links plus HTML escaping for rendered link hrefs and text.
- Updated README and registry behavior docs to describe proxy-root rendering.
- Verification:
  - `cargo test pypi` passed: 19 filtered tests passed.
  - `cargo test server` passed outside the sandbox: 18 server-filtered tests passed.
  - `cargo test e2e_pypi` passed: 2 PyPI e2e route tests passed.
- Commit: `daab70b`.

Problem:

- The proxy advertises `GET /pypi/simple/`, but currently returns upstream root HTML unchanged. Upstream root links can point clients at `/simple/<project>/`, which is not a supported proxy route.

Desired behavior:

- PyPI root responses keep clients on `/pypi/simple/<project>/` proxy routes, or the route is intentionally narrowed and docs are updated to avoid client-breaking claims.
- Prefer rewriting root links or rendering a minimal proxy-root HTML page when feasible.

Acceptance criteria:

- Add a test with upstream root HTML containing absolute `/simple/demo/`, relative `demo/`, and full upstream links, then verify returned links route through configured `server.public_base_url` plus `/pypi/simple/...`.
- Preserve HTML escaping for rendered links.
- Documentation accurately describes root behavior.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/pypi.rs`
- `src/server.rs`
- `docs/registry-behavior.md`
- `README.md`

Verification:

```sh
cargo test pypi
cargo test server
cargo test e2e_pypi
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 6: Final Regression and Docs Audit

Status note - 2026-07-05:

- Full regression passed after the async server/client migration, batch malicious checks, npm basename hardening, strict config validation, and PyPI root rewrite.
- Documentation audit updated README, registry behavior, and configuration docs during the relevant milestones; Tokio/concurrency behavior is implemented in code and covered by the idle-connection server test.
- Scope audit confirmed this goal did not add in-process metadata caching, local malicious storage, MongoDB/cachebox/S3 clients, artifact cache implementation, or proxy streaming. The required search command returns existing roadmap/docs/example/config-rejection references, plus config enum/test strings that reject unsupported modes; it does not show added implementation paths for those features.
- Verification:
  - `cargo test` passed outside the sandbox: 76 library tests, 0 main tests, 2 package-manager integration tests, and 0 doc tests.
  - `cargo fmt --check` passed after running `cargo fmt` for formatting-only changes.
  - `cargo clippy --all-targets --all-features -- -D warnings` passed.
  - `cargo run -- config validate --config examples/phase1/osv-proxy.yaml` passed and printed `configuration is valid for phase one`.
  - `rg -n "mongodb|cachebox|S3|proxy_cache_s3|memory cache|HashMap.*cache|artifact cache|proxy streaming" src examples docs` returned only existing docs/examples and config rejection references; no implementation of forbidden storage/cache/proxy features was added.
  - `git diff --check` passed.
- Commit: pending.

Problem:

- Async and hardening changes touch core request handling, adapter behavior, and user-facing docs. The repo must still match phase-one scope.

Desired behavior:

- Full regression passes.
- Docs and examples match implemented behavior.
- Scope audit confirms no forbidden storage/cache/proxy features were introduced.

Acceptance criteria:

- Full test, format, and clippy verification pass.
- Config example validates.
- Searches confirm no in-process metadata cache, local malicious store, MongoDB, cachebox, S3 artifact cache, or proxy streaming implementation was added.
- Docs mention Tokio/concurrency behavior only where it is implemented.
- Milestone status is marked done in this file and committed.

Likely files:

- `README.md`
- `docs/architecture.md`
- `docs/registry-behavior.md`
- `docs/configuration.md`
- `docs/internal/goal-05-concurrency-policy-hardening.md`

Verification:

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/phase1/osv-proxy.yaml
rg -n "mongodb|cachebox|S3|proxy_cache_s3|memory cache|HashMap.*cache|artifact cache|proxy streaming" src examples docs
git diff --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Final Response Required

When complete, report:

- Target state achieved or not achieved.
- Commits made, with hashes.
- Files changed.
- Exact verification commands run and results.
- Any intentionally deferred product scope.
- Known residual risks or follow-up issues.
