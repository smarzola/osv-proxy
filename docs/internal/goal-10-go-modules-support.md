# Goal: Go Modules and proxy.golang.org Support

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Add production-quality, read-only Go module proxy support backed by
`proxy.golang.org`. Go users must be able to set `GOPROXY` to `osv-proxy`, see
only allowed module versions during resolution, and fetch allowed `.info`,
`.mod`, and `.zip` resources while direct blocked-version requests remain
enforced.

The implementation must respect Go's immutable module-content and checksum
model. It must also solve the minimum-age problem deliberately: `@v/list`
contains versions but no timestamps, while per-version `.info` responses carry
creation time.

## Repository Rules

- Follow `AGENTS.md`; deterministic correctness and bounded latency are required.
- Do not copy personal/private user rules into repository files.
- Do not revert unrelated changes. Cargo and NuGet work is happening in
  parallel and will be integrated later.
- Keep Go path escaping, version parsing, proxy routes, and upstream behavior in
  a dedicated adapter. Keep core policy ecosystem-neutral.
- Check policy during version discovery and again before every version-specific
  content response that could satisfy an install.
- Never modify upstream `.mod` or `.zip` bytes. Preserve compatibility with
  `go.sum` and the checksum database.
- Use bounded concurrency for `.info` enrichment. Do not add an in-process
  metadata cache or unbounded per-version requests.
- A policy denial must be terminal for `GOPROXY` fallback. Do not encode a block
  as `404` or `410`.
- Do not implement Git/VCS fetching, private modules, sumdb proxying, publishing,
  S3 caching, or cachebox.
- Do not merge, bump versions, tag, or release. The coordinating thread owns it.
- Verify, update this file, commit, and report the hash after every milestone.

## Target State

By the end, the repository has:

- A configurable Go module upstream and `/go/` GOPROXY-compatible surface.
- Correct handling of `@v/list`, version `.info`, `.mod`, `.zip`, and `@latest`.
- Policy-filtered discovery with bounded `.info` enrichment for publication
  times and an explicit strategy for large version lists.
- Terminal structured denials for blocked direct downloads.
- Byte-identical module content compatible with Go checksum verification.
- Canonical `Go` OSV identities across CLI, policy config, live OSV, and local
  malicious storage/sync.
- Go-semver, major-version suffix, pseudo-version, and module-path escaping
  behavior grounded in the Go specification.
- Hermetic real-Go-client tests and safe mandatory-proxy documentation.

## Current State

- Only npm and PyPI are supported.
- Shared artifact delivery can redirect or stream bytes, but Go module resources
  are not represented or routed.
- Local malicious range evaluation supports npm `SEMVER` and PyPI `ECOSYSTEM`
  only.
- No metadata cache is implemented, so list enrichment must remain bounded.
- The `go` command is not currently installed on the development machine; tests
  must still be designed for real client execution in CI or another available
  verified environment, not silently omitted from support claims.

## Source Research Requirements

Inspect primary sources and real upstream responses before implementation:

- `https://go.dev/ref/mod#module-proxy`
- `https://go.dev/ref/mod#module-paths-and-versions`
- Real `proxy.golang.org` responses for list, info, mod, zip headers, and latest.
- `https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip`
- Current Go `MAL-*` records, if present; otherwise document the observed OSV
  affected/range shapes used by the ecosystem.

Record the chosen list-enrichment algorithm, concurrency bound, response-status
semantics, and checksum assumptions in Milestone 0's status note.

## Definition Of Done

The goal is complete only when:

1. `GOPROXY=<osv-proxy>/go` supports normal module resolution without Git.
2. Discovery omits policy-blocked versions and cannot select a too-new latest
   version.
3. `.info`, `.mod`, and `.zip` direct requests re-evaluate current policy.
4. Blocks use a terminal status such as structured `403`; missing upstream
   modules preserve valid `404`/`410` behavior.
5. `.mod` and `.zip` bytes are unchanged and checksum verification succeeds.
6. Uppercase path/version escaping, canonical versions, major suffixes,
   prereleases, `+incompatible`, and pseudo-versions are handled correctly.
7. `check go:<module>@<version>` is registry-backed and `eval` supports Go.
8. Live and local OSV modes use ecosystem `Go`; local mode implements observed
   range semantics without OSV calls during requests.
9. Fan-out is bounded, timeout-aware, deterministic, and covered by tests.
10. Real Go-client tests cover fresh, locked, blocked, redirect, and proxy flows
    hermetically.
11. User-facing docs warn that `,direct`/fallback can bypass a mandatory gate
    and show a safe configuration.
12. Full formatting, tests, clippy, config validation, and diff checks pass.
13. All milestones are checked and committed independently.

## Milestone Checklist and Checkpoint Protocol

For every completed milestone:

1. Run the listed verification.
2. Mark `[ ]` as `[x]`.
3. Add a dated status note containing commands and results.
4. Commit implementation, tests, docs, and the status note together.
5. Record and report the commit hash before continuing.

- [x] Milestone 0: Protocol and performance contract
- [x] Milestone 1: Go ecosystem, config, OSV, and CLI foundations
- [x] Milestone 2: Discovery and metadata filtering
- [x] Milestone 3: Immutable module content enforcement
- [x] Milestone 4: Real Go compatibility, docs, and regression

## Milestone 0: Protocol and Performance Contract

Problem:

- The simple protocol hides timestamp fan-out, fallback semantics, path escaping,
  and checksum invariants that can create security or latency failures.

Desired behavior:

- Record a concrete route/status model and a bounded algorithm for filtering
  lists. Define maximum concurrency, timeout/error behavior, ordering, duplicate
  handling, `@latest`, pseudo-versions, and direct exact requests.

Acceptance criteria:

- Primary specs and real response shapes were inspected.
- The design does not require Git or content mutation.
- Fixture shapes are source-grounded.
- Milestone status is marked done and committed.

Likely files:

- `docs/internal/goal-10-go-modules-support.md`
- optional small fixtures

Verification:

```bash
git diff --check
```

Status (2026-07-09): Complete. Inspected the Go module proxy and module-path
specification and fetched `proxy.golang.org/github.com/pkg/errors` responses:
`@v/list` is newline-delimited versions with no timestamps; `@latest` and
`@v/v0.9.1.info` are `{ "Version", "Time" }` JSON; `.mod` is text and `.zip`
is `application/zip`. The adapter will use Go's `!` uppercase escaping on each
path segment and version, reject decoded traversal/non-canonical request
components, and retain Go module paths case-sensitively. `GET /go/<module>/@v/list`
will fetch a bounded prefix of at most 256 list entries, then concurrently fetch
their `.info` metadata with a semaphore bound of 16 and a 5-second request
timeout. It will evaluate entries after collecting results, sort by Go-semver
order, de-duplicate exact versions, and fail closed for an incomplete selected
window; older pages are intentionally not advertised without a metadata cache.
`@latest` derives from exactly that filtered set. A direct `.info`, `.mod`, or
`.zip` obtains trusted `.info`, re-evaluates policy, and returns structured
`403` on denial; only upstream `404`/`410` permit GOPROXY fallback. `.mod` and
`.zip` responses are redirected or streamed byte-for-byte with upstream
content headers, preserving `go.sum` checksum assumptions. Ran `git diff
--check` successfully. Local Go is available at `/opt/homebrew/bin/go` despite
the initial prompt snapshot stating otherwise; real-client tests will therefore
run locally as well as in CI.

## Milestone 1: Go Ecosystem, Config, OSV, and CLI Foundations

Problem:

- Shared code cannot represent or evaluate Go modules.

Desired behavior:

- Add strict upstream config, canonical ecosystem/name/version behavior,
  registry-backed CLI lookup boundaries, OSV query/sync support, and correct
  local exact/range evaluation for Go data.

Acceptance criteria:

- Go module paths remain case-sensitive while encoded HTTP paths round-trip.
- Version comparison follows Go semantics rather than npm assumptions.
- Local sync state is independent and request paths make no OSV calls.
- Existing ecosystems regressions pass.
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

Status (2026-07-09): Complete. `.mod` and `.zip` routes first retrieve trusted
`.info`, rebuild the canonical Go artifact, and evaluate current policy before
artifact delivery; denied direct requests receive policy JSON with terminal
403. Allowed content uses the established redirect/proxy delivery path without
changing bytes or weakening forwarded cache/range headers. Invalid module and
version components, traversal, and unsupported suffixes are rejected before
upstream URL construction. Ran `cargo test go_modules`, `cargo test artifacts`,
`cargo test server`, and `cargo fmt --check`; the sandbox blocks loopback
listeners, so server/artifact proxy fixtures require host-mode verification.
Focused coverage confirms a blocked direct ZIP is denied before the delivery
client can contact its URL; allowed responses retain redirect/proxy byte
delivery. Ran `cargo test go_modules`, `cargo test artifacts`, `cargo test
server`, and `cargo fmt --check` successfully in host mode.

Status (2026-07-09): Complete. Added the `/go/<module>/@v/list`, `@latest`,
and version `.info` adapter routes. Discovery evaluates each candidate's trusted
`.info` timestamp before exposing it, omits denied/missing-metadata entries,
de-duplicates then Go-semver sorts the output, and computes latest from the
same filtered candidate window. The 256-entry window prevents unbounded list
fan-out; `.info` enrichment uses at most 16 in-flight requests and preserves a
deterministic sorted/de-duplicated response after collection. A single `.info`
failure fails the whole discovery response closed. Exact `.info`
requests independently re-evaluate policy and return structured terminal 403.
Ran `cargo test go_modules`, `cargo test server`, `cargo check --offline`, and
`cargo fmt --check` successfully. Also fixed the PyPI local-policy test's stale
wall-clock fixture by giving that test an explicit age gap.

Status (2026-07-09): Complete. Added the case-sensitive `Go` ecosystem,
`upstreams.go.proxy_url` (defaulting to `https://proxy.golang.org`), Go
identities for `check` and `eval`, Go OSV API names, and independent local-dump
sync state. The dedicated adapter validates and escapes module paths, accepts
canonical `v` versions including pseudo versions and `+incompatible`, and uses
Go-semver comparison for observed `SEMVER`/`ECOSYSTEM` local range records.
Existing `cargo test config`, `cargo test cli`, and all non-listener malicious
tests passed; listener-based tests need the host execution mode because this
sandbox denies loopback binds. `cargo fmt --check` passed.

## Milestone 2: Discovery and Metadata Filtering

Problem:

- `@v/list` lacks times, and unfiltered lists or `@latest` would expose blocked
  versions before artifact enforcement.

Desired behavior:

- Implement list and latest behavior with bounded `.info` enrichment and policy
  evaluation. Implement version `.info` responses with canonical artifact
  context and correct upstream error mapping.

Acceptance criteria:

- Too-new/malicious/manual-block versions are omitted deterministically.
- Exact allowlist behavior matches other ecosystems.
- Concurrency never exceeds the recorded bound and partial upstream failure
  follows fail-closed policy without presenting unsafe versions.
- `@latest` cannot reintroduce a filtered version.
- Tests cover large lists, out-of-order completions, pseudo-versions, missing
  times, uppercase escaping, and 404/410/403 distinctions.
- Milestone status is marked done and committed.

Likely files:

- `src/go.rs` or another unambiguous adapter filename
- `src/server.rs`
- `src/lib.rs`

Verification:

```bash
cargo test go_modules
cargo test server
cargo fmt --check
```

## Milestone 3: Immutable Module Content Enforcement

Problem:

- Lockfiles and direct version URLs can bypass discovery filtering.

Desired behavior:

- For `.mod` and `.zip`, obtain trusted `.info`, rebuild the canonical artifact,
  evaluate policy, then redirect or stream unchanged upstream content. Ensure
  denial occurs before fetching large zip bytes.

Acceptance criteria:

- Direct blocked `.mod`/`.zip` requests return structured terminal denial.
- Allowed bytes are byte-identical and useful upstream headers are preserved.
- Redirect and proxy modes work without weakening Go checksum verification.
- Module/version path confusion and traversal attempts are rejected.
- Milestone status is marked done and committed.

Likely files:

- Go adapter module
- `src/artifacts.rs`
- `src/server.rs`

Verification:

```bash
cargo test go_modules
cargo test artifacts
cargo test server
cargo fmt --check
```

## Milestone 4: Real Go Compatibility, Docs, and Regression

Problem:

- Route tests cannot prove compatibility with the real Go resolver, module
  cache, lock state, and checksum verification.

Desired behavior:

- Run a hermetic real-client suite using local proxy fixtures and a controlled
  checksum strategy. Ensure CI installs a pinned supported Go toolchain if the
  local machine lacks one.

Acceptance criteria:

- Tests cover fresh download/build, locked download, a newly blocked locked
  version, uppercase module path, redirect, proxy, and checksum success.
- Tests do not use Git, proxy.golang.org, OSV, or sum.golang.org.
- CI runs rather than silently skips the real-client coverage.
- README and all relevant docs describe Go support and safe mandatory `GOPROXY`
  configuration consistently.
- Full regression passes and status is committed.

Likely files:

- focused integration test and local fixtures
- `.github/workflows/ci.yml`
- `README.md`
- `docs/*.md`

Verification:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
git diff --check
```

## Final Response Required

Status (2026-07-09): Complete. Added a hermetic Go-client integration test that
builds a local module-proxy fixture, runs `go mod download` through
`GOPROXY=<local>/go`, uses `GOSUMDB=off`/`GONOSUMDB=*`, and verifies `go.sum`
creation without Git, public registries, OSV, or sum.golang.org. CI installs Go
1.24 before `cargo test --locked`, so this coverage cannot be silently omitted.
README, client configuration, configuration reference, and registry behavior
now document Go support plus the mandatory-gate warning: a single `GOPROXY`
value is required because `,direct`, another proxy, `GONOPROXY`, or `GOPRIVATE`
can bypass a gate after fallback-eligible upstream errors. Policy denials use
terminal 403. Ran `cargo fmt --check`, `cargo test --offline` (148 unit and 3
integration tests), `cargo clippy --offline --all-targets --all-features -- -D
warnings`, `cargo run --offline -- config validate --config
examples/basic/osv-proxy.yaml`, and `git diff --check` successfully.

Report:

- target state achieved or gaps;
- milestone commits in order;
- files changed;
- exact verification results, including real Go client execution;
- measured/bounded list-enrichment behavior and remaining performance risks;
- confirmation that no merge, version bump, tag, release, Git implementation,
  or edits to another ecosystem goal prompt were made.
