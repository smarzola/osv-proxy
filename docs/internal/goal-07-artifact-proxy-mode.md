# Goal: Artifact Proxy Mode

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Deliver plain artifact proxy mode for `osv-proxy`. Metadata filtering must keep
rewriting package artifact URLs through `osv-proxy`, but when
`artifacts.behavior: proxy` is configured, allowed npm tarballs and PyPI files
must be streamed back through the proxy instead of returning a redirect.

Keep this goal scoped to proxy mode only. Do not implement S3 artifact caching,
metadata caching, local malicious storage, MongoDB/mongolino sync, publishing,
authentication, license policy, vulnerability severity policy, or broad package
scanning.

Track this work against `docs/milestones.md` Milestone 7, but split
`proxy_cache_s3` into a future milestone. This goal completes the plain proxy
streaming part only.

## Repository Rules

- Implementation code is explicitly requested for this goal.
- Follow `AGENTS.md`: correctness and performance are first-class because this
  code runs in the package-install path.
- Do not revert unrelated user changes. You are not alone in this codebase.
- Preserve the invariant that policy is checked during metadata generation and
  checked again during artifact serving.
- Preserve redirect mode as the default and keep its existing behavior.
- Keep npm/PyPI route parsing and ecosystem metadata interpretation inside
  `src/npm.rs` and `src/pypi.rs`.
- Put shared artifact delivery behavior in a shared module instead of
  duplicating byte-proxy logic in both adapters.
- If tests expose a real product gap, fix the product rather than weakening the
  test.
- At the end of each milestone, run verification, mark the milestone done in
  this file, commit the completed milestone, and report the commit hash before
  continuing.

## Target State

By the end, the repo should have:

- A supported YAML config section:

  ```yaml
  artifacts:
    behavior: proxy
  ```

- `redirect` remains the default artifact behavior.
- In redirect mode, allowed artifact requests still return `302 Location` to
  the upstream tarball or file URL after the second policy check.
- In proxy mode, allowed artifact requests fetch the verified upstream artifact
  URL and stream the upstream response body through `osv-proxy`.
- Blocked artifact requests return the existing structured `403` policy
  response and do not fetch upstream artifact bytes.
- Upstream artifact fetch failures map to clear gateway-style responses.
- npm and PyPI metadata filtering behavior remains unchanged except for docs
  explaining that artifact URLs route through `osv-proxy` and final delivery is
  selected by config.
- S3 cache mode remains unsupported and rejected until a separate goal
  implements it.

## Current State

- `src/npm.rs` and `src/pypi.rs` build canonical artifacts and re-evaluate
  policy on direct artifact routes.
- Allowed npm and PyPI artifact routes currently call `RegistryResponse::redirect`.
- `src/response.rs` stores response bodies as `Vec<u8>`, which is fine for JSON
  and HTML but not a good streaming representation for package artifacts.
- `src/config.rs` currently rejects any top-level `artifacts` section.
- `docs/registry-behavior.md` and README state that proxy mode is not
  implemented.

## Definition Of Done

The goal is complete only when:

1. `artifacts.behavior` accepts `redirect` and `proxy`; default is `redirect`.
2. `artifacts.behavior: proxy_cache_s3` remains rejected with a clear unsupported
   configuration error.
3. npm allowed artifact requests in proxy mode stream upstream bytes and status
   after the existing second policy check.
4. PyPI allowed artifact requests in proxy mode stream upstream bytes and status
   after the existing second policy check.
5. Blocked npm and PyPI artifact requests do not fetch upstream artifact bytes.
6. Redirect mode tests continue to prove `302 Location` behavior.
7. Proxy mode handles upstream artifact HTTP failures without panicking or
   returning misleading policy decisions.
8. Request/response handling avoids buffering full package artifacts in memory
   in the real Axum server path.
9. README, configuration docs, registry behavior docs, and milestones reflect
   plain proxy mode support while keeping S3 cache marked future/unsupported.
10. `cargo test` passes.
11. `cargo fmt --check` passes.
12. `cargo clippy --all-targets --all-features -- -D warnings` passes.
13. Milestone checkboxes in this file are marked `[x]` as work completes.
14. Each completed milestone has a focused commit.

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

- [x] Milestone 0: Baseline and delivery contract
- [x] Milestone 1: Artifact behavior config
- [x] Milestone 2: Shared artifact delivery layer
- [ ] Milestone 3: npm and PyPI proxy-mode integration
- [ ] Milestone 4: Docs and final regression

## Milestone 0: Baseline and Delivery Contract

Problem:

- Proxy mode touches config, HTTP body handling, npm/PyPI adapter behavior, and
  package-manager-facing docs. The delivery contract must be explicit before
  implementation starts.

Desired behavior:

- Establish the baseline test state and record the exact contract for redirect,
  proxy, and still-unsupported S3 cache behavior.

Acceptance criteria:

- Run baseline verification commands and record results in this milestone's
  status note.
- Record the selected implementation contract in this file's status note.
- Do not change implementation behavior in this milestone except for the status
  note.
- Milestone status is marked done in this file and committed.

Likely files:

- `docs/internal/goal-07-artifact-proxy-mode.md`

Verification:

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note (2026-07-06):

- Baseline verification: `cargo test` failed inside the sandbox because
  `server::tests::idle_connection_does_not_block_unrelated_request` hit
  `Operation not permitted` on local socket setup; reran `cargo test` outside
  the sandbox and it passed with 95 lib tests, 0 main tests, 2 package-manager
  e2e tests, and 0 doctests. `cargo fmt --check` passed. `cargo clippy
  --all-targets --all-features -- -D warnings` passed.
- Selected implementation contract: `artifacts.behavior` defaults to
  `redirect`; `proxy` streams allowed upstream npm/PyPI artifact responses after
  the existing second policy check; blocked artifacts keep returning structured
  `403` responses without fetching artifact bytes; `proxy_cache_s3` remains
  rejected as unsupported for a future milestone.
- Commit: pending.

## Milestone 1: Artifact Behavior Config

Problem:

- The config model currently rejects all `artifacts` configuration, so operators
  cannot select proxy mode.

Desired behavior:

- Add an `artifacts` config section with `behavior: redirect` by default and
  `behavior: proxy` supported.
- Reject `proxy_cache_s3` until S3 cache mode is implemented.

Acceptance criteria:

- `Config::default()` uses redirect behavior.
- YAML with `artifacts.behavior: redirect` validates.
- YAML with `artifacts.behavior: proxy` validates.
- YAML with `artifacts.behavior: proxy_cache_s3` is rejected as unsupported.
- Unknown nested artifact config keys are rejected.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/config.rs`
- `docs/internal/goal-07-artifact-proxy-mode.md`

Verification:

```sh
cargo test config
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note (2026-07-06):

- Implemented `artifacts.behavior` with default `redirect`, supported `redirect`
  and `proxy`, unsupported `proxy_cache_s3`, and unknown nested artifact keys
  rejected by config deserialization.
- Verification: `cargo test config` passed with 22 tests; `cargo fmt --check`
  passed.
- Commit: pending.

## Milestone 2: Shared Artifact Delivery Layer

Problem:

- `RegistryResponse` is currently byte-vector based and redirect-only for
  artifacts. Proxy mode needs a shared way to deliver artifact bytes without
  buffering complete package files in the live server path.

Desired behavior:

- Introduce a shared artifact delivery module that can return either redirect
  responses or proxied upstream responses.
- Keep artifact delivery independent from npm/PyPI parsing.
- Preserve safe HTTP behavior by forwarding only useful artifact headers and
  not forwarding hop-by-hop headers.

Acceptance criteria:

- Shared delivery code supports redirect and proxy behavior.
- Proxy behavior forwards useful request headers such as `Range`,
  `If-None-Match`, and `If-Modified-Since` when available.
- Proxy behavior preserves useful upstream response headers such as
  `Content-Type`, `Content-Length`, `ETag`, `Last-Modified`,
  `Accept-Ranges`, `Content-Range`, and cache-related headers when present.
- Hop-by-hop headers are not forwarded.
- The Axum route path can stream proxied artifacts without collecting the full
  package body into memory.
- Test helper paths remain usable for existing unit tests, even if streaming is
  represented differently there.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/artifacts.rs`
- `src/response.rs`
- `src/server.rs`
- `src/lib.rs`
- `Cargo.toml`
- `docs/internal/goal-07-artifact-proxy-mode.md`

Verification:

```sh
cargo test artifacts
cargo test server
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

Status note (2026-07-06):

- Added a shared artifact delivery module with redirect and proxy delivery,
  selected request-header forwarding, selected upstream response-header
  forwarding, gateway-style fetch errors, buffered helper conversion for tests,
  and streaming Axum HTTP conversion for live responses. Enabled the `reqwest`
  `stream` feature and updated `Cargo.lock`.
- Verification: `cargo test artifacts` initially required network outside the
  sandbox to resolve the new `reqwest` streaming dependency, then passed with 8
  tests; `cargo test server` passed with 19 tests; `cargo fmt --check` passed.
- Commit: pending.

## Milestone 3: npm and PyPI Proxy-Mode Integration

Problem:

- npm and PyPI artifact routes currently stop at redirect responses after the
  second policy check. Proxy mode must reuse the same validated artifact and
  policy result, then deliver bytes according to config.

Desired behavior:

- npm tarball routes use shared artifact delivery after successful policy
  evaluation.
- PyPI file routes use shared artifact delivery after successful policy
  evaluation.
- Blocked artifacts return structured `403` responses and do not fetch upstream
  bytes.

Acceptance criteria:

- npm proxy-mode test proves allowed tarball requests return upstream bytes and
  useful upstream headers.
- PyPI proxy-mode test proves allowed file requests return upstream bytes and
  useful upstream headers.
- npm and PyPI blocked-artifact tests prove the artifact byte upstream is not
  contacted.
- Redirect-mode tests remain intact.
- Upstream artifact fetch errors map to a clear non-2xx gateway response.
- Milestone status is marked done in this file and committed.

Likely files:

- `src/npm.rs`
- `src/pypi.rs`
- `src/server.rs`
- `tests/package_manager_e2e.rs`
- `docs/internal/goal-07-artifact-proxy-mode.md`

Verification:

```sh
cargo test npm
cargo test pypi
cargo test server
cargo test --test package_manager_e2e
cargo fmt --check
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Milestone 4: Docs and Final Regression

Problem:

- User-facing docs currently describe redirect-only behavior and list artifact
  proxying as unimplemented.

Desired behavior:

- Documentation accurately describes redirect and proxy modes, configuration,
  current limitations, and future S3 cache mode.
- Final regression proves the repo is ready for release prep.

Acceptance criteria:

- README current scope and policy behavior mention proxy mode correctly.
- `docs/configuration.md` documents `artifacts.behavior`.
- `docs/registry-behavior.md` documents redirect and proxy behavior.
- `docs/milestones.md` marks plain proxy mode as implemented or split from
  future S3 cache work.
- Final verification commands pass or any environment-only failures are
  documented with evidence and rerun outside the sandbox if needed.
- Milestone status is marked done in this file and committed.

Likely files:

- `README.md`
- `docs/configuration.md`
- `docs/registry-behavior.md`
- `docs/milestones.md`
- `docs/internal/goal-07-artifact-proxy-mode.md`

Verification:

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
rg -n "proxy_cache_s3|S3|artifact proxying|proxy mode|artifacts:" README.md docs src examples
```

Commit requirement:

- Commit after marking this milestone done and adding the status note.

## Final Verification

Before reporting the implementation complete, run:

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
git status --short
```

## Final Response Required

When complete, report:

- target state achieved or not achieved;
- commits made;
- files changed;
- exact verification commands run and results;
- known residual risks or follow-up issues;
- any skipped checks with concrete reasons.
