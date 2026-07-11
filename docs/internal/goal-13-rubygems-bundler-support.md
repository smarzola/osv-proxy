# Goal: RubyGems and Bundler Restore Support

Work in `/Users/smarzola/projects/osv-proxy` on branch
`feat/rubygems-bundler-support`, starting from `main` commit `c07821a`.

Add production-quality, read-only RubyGems support for modern Bundler restore
workflows backed by rubygems.org. `bundle install` must resolve only
policy-allowed gem versions and download allowed `.gem` artifacts through the
existing redirect or proxy delivery modes.

Source of truth: this prompt, the official RubyGems Compact Index/API
documentation, observed rubygems.org response shapes, and the repository's
existing package-adapter invariants.

## Target State

When this goal is complete:

- Bundler can use `/rubygems/` as its only source for fresh and locked installs.
- Compact Index package information excludes blocked, vulnerable, malicious,
  too-new, yanked, malformed, or otherwise unevaluable gem variants.
- Allowed `.gem` downloads use existing redirect/proxy modes; every direct
  download is independently resolved and policy-checked before delivery.
- RubyGems package names, versions, and platforms are handled with ecosystem-
  correct semantics, including RubyGems version ordering for local OSV ranges.
- Live and local OSV use the canonical `RubyGems` ecosystem, and registry-backed
  `check rubygems:<name>@<version>` reports every matching platform artifact.
- CI runs hermetic real-Bundler coverage, and operator docs accurately describe
  supported configuration and the intentionally narrower protocol scope.

## Current-State Evidence

Verified before this prompt was written:

- `src/artifact.rs::Ecosystem` supports npm, PyPI, Go, crates.io, and NuGet but
  has no RubyGems identity or normalization.
- `src/config.rs::UpstreamsConfig` has one upstream section per supported
  adapter and no RubyGems registry URL.
- `src/malicious.rs::sync_osv` synchronizes the five current ecosystem dumps;
  `range_matches_artifact` deliberately uses ecosystem-specific comparators.
- `src/server.rs` owns routing and composes adapter clients with the shared
  policy checker and artifact-delivery modes.
- `tests/package_manager_e2e.rs` contains hermetic real-client tests for all five
  current ecosystems; `.github/workflows/ci.yml` installs their toolchains but
  does not install a pinned Ruby toolchain.
- RubyGems documents the Compact Index as a stable API. `/versions` is a global
  append-oriented index; `/info/<gem>` contains dependency, version, platform,
  Ruby/RubyGems requirements, and uploaded-gem checksum data. Compact endpoints
  use ETags, ranges, and representation digests.
- The observed `/api/v1/versions/<gem>.json` response provides all variants for
  one gem, including version, platform, `created_at`, yanked state, and SHA-256.
- OSV publishes a canonical `RubyGems` ecosystem dump.

Unknowns that may affect implementation details, but not the target state:

- Exact Range fallback behavior across supported Bundler releases must be
  confirmed with hermetic client tests.
- Artifact filenames can be ambiguous when names, versions, and platforms
  contain hyphens; resolution must be proven against upstream metadata rather
  than relying on an unverified filename split.

## Constraints And Non-Goals

Follow `AGENTS.md`; correctness and install-path performance are mandatory.

- Keep RubyGems protocol parsing, normalization, upstream access, filtered
  representation generation, and response mapping in a dedicated adapter.
- Keep shared policy and delivery logic ecosystem-neutral.
- Perform one bounded per-package metadata correlation for Compact Index
  filtering and batch OSV evaluation; do not add an in-process metadata cache.
- Preserve compact dependency/requirement fields and `.gem` bytes exactly.
- Recheck policy before every `.gem` redirect or streamed response.
- Treat unsupported/malformed metadata and ambiguous identities as fail-closed
  gateway errors; do not guess a downloadable artifact identity.
- Preserve all existing package adapters and tests.
- Scope the first release to current Bundler Compact Index restore. Do not add
  legacy `specs.4.8.gz`, `latest_specs.4.8.gz`,
  `quick/Marshal.4.8`, dependency API, search, publishing, yank/delete,
  authentication, private registries, or gem hosting.
- Do not add S3/cachebox behavior, a metadata cache, or repack artifacts.
- Do not bump versions, push, open a PR, tag, publish, or release.
- Preserve unrelated user changes and work safely in a dirty worktree.

## Authorization And Decisions

This goal authorizes repository inspection, in-scope local edits, focused
Conventional Commits, branch-local checkpoints, reviewer-thread orchestration,
and relevant non-destructive verification.

Require confirmation before destructive actions, external writes or
publication, purchases, secrets or permission changes, or a material expansion
of scope unless separately authorized by the user.

Continue through routine implementation choices using repository evidence. Ask
only when ambiguity materially changes user-visible behavior, architecture,
data compatibility, security posture, or authorization. Otherwise choose the
least-surprising in-scope interpretation and record it in the next status note.

Before declaring a blocker, exhaust safe in-scope alternatives. If still
blocked, report the condition, evidence, and smallest decision or external
change needed. Do not claim completion.

Decision: `/rubygems/versions` may preserve the upstream global version
representation because filtering it would require evaluating every release of
every gem. `/rubygems/info/<gem>` is the authoritative resolver gate and must
exclude every denied variant. Direct artifact requests remain independently
protected, so the global index cannot bypass policy.

Decision: filtered Compact Index responses own their ETag, representation
digest, conditional, and range semantics. They must not forward validators that
describe the unfiltered upstream representation.

## Success Criteria

The goal is complete only when:

1. A real supported Bundler client completes fresh and locked dependency
   installs with only the proxy source and no rubygems.org fallback.
2. `/rubygems/info/<gem>` preserves allowed dependency/platform records and
   excludes blocked, too-new, yanked, malformed, and policy-error variants.
3. Compact responses correctly implement full, conditional, and byte-range
   behavior with validators/digests for the filtered representation.
4. Direct `.gem` requests validate an exact upstream name/version/platform/
   filename/hash tuple, recheck policy, and cannot bypass the proxy.
5. Allowed redirect and proxy modes preserve bytes; denials are structured
   `403`, missing/yanked artifacts are `404`, and invalid/upstream failures are
   deterministic `502` responses.
6. RubyGems version comparison matches representative `Gem::Version` ordering,
   including prereleases, and local OSV exact/range evaluation works without
   request-path network calls.
7. Live/local OSV use `RubyGems`; local sync includes its dump; CLI `check` and
   `eval` support RubyGems identities and platform variants.
8. Unit, route, and real-client tests cover dependencies, platforms,
   prereleases, minimum age, blocklist/OSV denial, fresh/locked installs,
   redirect, proxy, direct-download bypass attempts, and upstream errors.
9. CI provisions a pinned supported Ruby/Bundler environment and executes the
   real-client coverage without silently skipping it.
10. README, configuration, client, behavior, OSV-data, and milestone docs state
    the supported RubyGems/Bundler surface and legacy-protocol non-goals.
11. Every milestone is checked off with verification evidence, adversarial
    review, and a focused Conventional Commit.
12. Final formatting, tests, clippy, config validation, diff checks, and an
    independent full-goal audit pass.

## Milestones

- [x] Milestone 1: RubyGems identity, configuration, OSV, and CLI foundations
- [ ] Milestone 2: Policy-filtered Compact Index with cache/range semantics
- [ ] Milestone 3: Protected `.gem` delivery and deterministic error mapping
- [ ] Milestone 4: Real Bundler workflows, documentation, and full regression

### Checkpoint Protocol

At the end of each milestone:

1. Satisfy its acceptance criteria.
2. Run its verification commands and inspect the results.
3. Freeze main-thread writes and obtain adversarial read-only review. Repair and
   re-review until no blocking findings remain.
4. Mark its checkbox `[x]` and add a dated status note under that milestone with
   the outcome, exact commands, results, and review disposition.
5. Commit the implementation, tests, docs, and this prompt update together with
   a focused Conventional Commit.
6. Report the resulting commit hash before starting the next milestone.

If verification fails, leave the milestone unchecked and do not make its
checkpoint commit. Diagnose and repair in-scope failures. A commit cannot
contain its own final hash, so report the hash after committing.

## Milestone 1: RubyGems Foundations

Why this matters:

- Shared identity, OSV storage, RubyGems version semantics, and registry-backed
  CLI lookup must be correct before HTTP metadata can enforce policy.

Acceptance criteria:

- RubyGems ecosystem/config identities are normalized consistently across CLI,
  policy lists, URLs, SQLite, and OSV queries.
- RubyGems-aware version ordering is covered against representative
  `Gem::Version` results and used for local OSV `ECOSYSTEM` ranges.
- Local synchronization includes `RubyGems/all.zip` with independent state.
- Registry-backed `check` returns all exact version/platform variants with
  publication timestamps, filenames, URLs, and SHA-256 hashes.

Likely touchpoints (non-exhaustive):

- `src/artifact.rs`
- `src/config.rs`
- `src/cli.rs`
- `src/malicious.rs`
- `src/lib.rs`
- `src/rubygems.rs`
- `examples/basic/osv-proxy.yaml`

Verification:

```bash
cargo test artifact::tests
cargo test config::tests
cargo test cli::tests
cargo test malicious::tests
cargo test rubygems::tests
cargo fmt --check
git diff --check
```

Status (2026-07-11): Complete. Added canonical `RubyGems` ecosystem identity
and aliases, strict upstream configuration, registry-backed exact-version lookup
across all non-yanked platform variants, canonical filename/URI/SHA validation,
local dump synchronization, and ecosystem-range evaluation with RubyGems
`Gem::Version` ordering. Arbitrarily large numeric segments are supported.
Adversarial review found two blockers: mixed separator grammar accepted invalid
versions and name validation rejected valid trailing punctuation. Both were
verified against installed RubyGems, repaired, regression-tested, and the
re-review reported no blocking findings. Malformed upstream versions now fail
closed. Verification: `cargo test artifact::tests` (7 passed), `cargo test
config::tests` (33 passed), `cargo test cli::tests` (14 passed), `cargo test
malicious::tests` (51 passed), `cargo test rubygems::tests` (5 passed), `cargo
fmt --check` (passed), and `git diff --check` (passed).

## Milestone 2: Policy-Filtered Compact Index

Why this matters:

- Bundler dependency resolution must never select a denied gem variant, and its
  cache protocol must remain correct for a policy-derived representation.

Acceptance criteria:

- Owned `/rubygems/versions` and `/rubygems/info/<gem>` routes keep the client
  on the proxy and expose no unsupported mutable/write surface.
- Package info correlates compact lines with bounded upstream version metadata,
  batch-evaluates policy, preserves allowed lines exactly, and fails closed on
  missing, duplicate, ambiguous, or malformed correlation.
- Filtered responses have correct content type, ETag, representation digest,
  `If-None-Match`, `Range`, `If-Range`, `206`, `304`, and `416` behavior.
- Route tests prove denial and minimum-age transitions cannot be bypassed by
  cached or ranged requests.

Likely touchpoints (non-exhaustive):

- `src/rubygems.rs`
- `src/server.rs`
- `src/response.rs`

Verification:

```bash
cargo test rubygems::tests
cargo test server::tests
cargo fmt --check
git diff --check
```

Status: Not started.

## Milestone 3: Protected Gem Delivery

Why this matters:

- A direct artifact URL must not bypass metadata filtering or map an ambiguous
  filename to the wrong package identity.

Acceptance criteria:

- Requested filenames resolve to exactly one upstream metadata tuple and are
  rejected when absent, yanked, ambiguous, malformed, or checksum-inconsistent.
- Allowed redirect/proxy delivery preserves exact bytes and relevant headers;
  every request receives a fresh policy decision before delivery.
- Denials, not-found states, and upstream/metadata failures use deterministic
  structured status mapping and do not contact artifact upstreams when denied.
- Unit/route tests cover hyphenated names, versions, platforms, prereleases,
  bad basenames, mismatched hashes, both delivery modes, and bypass attempts.

Likely touchpoints (non-exhaustive):

- `src/rubygems.rs`
- `src/server.rs`
- `src/artifacts.rs`

Verification:

```bash
cargo test rubygems::tests
cargo test server::tests
cargo test artifacts::tests
cargo fmt --check
git diff --check
```

Status: Not started.

## Milestone 4: Real Bundler Integration And Documentation

Why this matters:

- Protocol compatibility must be established with the actual client, and users
  need an accurate configuration/support contract.

Acceptance criteria:

- Hermetic real-Bundler tests cover dependency restore, platform selection,
  prerelease, fresh/locked denial, and redirect/proxy delivery without external
  registry fallback.
- CI installs pinned Ruby/Bundler tooling and cannot silently skip the tests.
- User/operator docs and examples cover RubyGems configuration, routes, CLI,
  upstream defaults, OSV data, and explicit legacy/publish non-goals.
- Every existing ecosystem client test and full repository gate remains green.

Likely touchpoints (non-exhaustive):

- `tests/package_manager_e2e.rs`
- `.github/workflows/ci.yml`
- `README.md`
- `docs/client-configuration.md`
- `docs/configuration.md`
- `docs/registry-behavior.md`
- `docs/osv-data.md`
- `docs/milestones.md`

Verification:

```bash
cargo test --test package_manager_e2e
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
git diff --check
```

Status: Not started.

## Final Verification

Run from `/Users/smarzola/projects/osv-proxy`:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
git diff --check
git status --short
```

Do not treat a checkbox or commit as proof that a command passed. Inspect
failures. Fix in-scope regressions rather than weakening tests. For an unrelated
pre-existing failure, record the command, result summary, and evidence that the
goal did not cause it.

## Resume Protocol

On a resumed session, first read this prompt, `AGENTS.md`, `git status`, status
notes, and recent commits. Verify completed checkpoints and continue from the
first unchecked milestone; do not redo completed work. New evidence may refine
implementation details but must not silently weaken target state or success
criteria.

## Final Report

Lead with `Achieved` or `Not achieved`, then report:

- target state and success criteria status;
- branch and milestone checkpoint commits;
- files changed;
- exact verification commands and results;
- reviewer rounds and disposition;
- residual risks, follow-ups, and external delivery steps that remain
  unauthorized or incomplete.
