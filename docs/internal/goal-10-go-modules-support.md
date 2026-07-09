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

- [ ] Milestone 0: Protocol and performance contract
- [ ] Milestone 1: Go ecosystem, config, OSV, and CLI foundations
- [ ] Milestone 2: Discovery and metadata filtering
- [ ] Milestone 3: Immutable module content enforcement
- [ ] Milestone 4: Real Go compatibility, docs, and regression

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

Report:

- target state achieved or gaps;
- milestone commits in order;
- files changed;
- exact verification results, including real Go client execution;
- measured/bounded list-enrichment behavior and remaining performance risks;
- confirmation that no merge, version bump, tag, release, Git implementation,
  or edits to another ecosystem goal prompt were made.

