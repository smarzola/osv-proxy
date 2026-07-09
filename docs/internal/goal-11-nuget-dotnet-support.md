# Goal: NuGet Registry and .NET Restore Support

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Add production-quality, read-only NuGet V3 support for `.NET` restore workflows
backed by nuget.org. `dotnet restore` and compatible NuGet clients must discover
only policy-allowed package versions and download allowed `.nupkg` artifacts
through the existing redirect or proxy delivery modes.

Scope the first implementation to restore-critical resources: the V3 service
index, registrations, and package base address/flat container. Do not turn this
goal into a complete NuGet Gallery, publishing server, or IDE search service.

## Repository Rules

- Follow `AGENTS.md`; correctness and install-path performance are mandatory.
- Do not copy personal/private user rules into repository files.
- Do not revert unrelated work. Cargo and Go adapters are being developed in
  parallel and will be integrated later.
- Keep NuGet service discovery, ID/version normalization, registrations, and
  flat-container behavior in a dedicated adapter. Keep policy generic.
- Filter version discovery and recheck policy before `.nupkg` delivery.
- Preserve package bytes and hashes exactly; never repack `.nupkg` files.
- Use bounded requests when flat-container version lists must be correlated with
  registration metadata. Do not add an in-process metadata cache.
- Treat unlisted packages and nuget.org's year-1900 `published` sentinel
  deliberately; do not accidentally classify it as an ancient allowed package.
- Do not implement package publishing/delete, authentication, symbols, search
  UI, vulnerability severity policy, S3 caching, or cachebox.
- Do not merge, bump versions, tag, or release. Integration is owned elsewhere.
- Verify, update this file, commit, and report the hash after every milestone.

## Target State

By the end, the repository has:

- A configurable nuget.org V3 upstream and `/nuget/v3/` proxy surface.
- A service index advertising only supported proxy-owned resource URLs.
- Policy-filtered registration indexes/pages/leaves with internal URLs rewritten
  through `osv-proxy`.
- Policy-filtered flat-container version enumeration and protected `.nupkg` and
  `.nuspec` retrieval required for restore.
- Minimum-age evaluation from NuGet registration/catalog publication metadata.
- Correct package ID and NuGet version normalization, including prereleases and
  SemVer 2 behavior required by real clients.
- Canonical `NuGet` OSV support in CLI, live queries, and local sync/evaluation.
- Hermetic real `dotnet restore` tests and operator documentation.

## Current State

- The proxy supports only npm and PyPI protocols.
- Shared artifact delivery supports redirects and streaming.
- Config, CLI, local sync, and range evaluation have no NuGet ecosystem.
- The `dotnet` command is not installed locally; real-client tests must run in a
  verified CI/toolchain environment and must not be silently skipped.
- No metadata cache exists, so registration correlation must be bounded and
  latency-conscious.

## Source Research Requirements

Inspect primary documentation and real nuget.org shapes before implementation:

- `https://learn.microsoft.com/nuget/api/service-index`
- `https://learn.microsoft.com/nuget/api/registration-base-url-resource`
- `https://learn.microsoft.com/nuget/api/package-base-address-resource`
- `https://learn.microsoft.com/nuget/concepts/package-versioning`
- Real `https://api.nuget.org/v3/index.json`, registration, flat-container, and
  `.nuspec` responses for a small package.
- `https://storage.googleapis.com/osv-vulnerabilities/NuGet/all.zip`

Record the minimum restore resource set, URL-rewrite graph, unlisted-package
semantics, timestamp source, normalization rules, and request bounds in the
Milestone 0 status note.

## Definition Of Done

The goal is complete only when:

1. A real `dotnet restore` can use only the proxy source for public packages.
2. The V3 service index points clients exclusively at supported proxy routes.
3. Registration and flat-container discovery omit blocked and too-new versions.
4. Registration links and `packageContent` cannot bypass the proxy.
5. Direct blocked `.nupkg` downloads return structured `403` before bytes are
   fetched; allowed redirect and proxy modes preserve bytes.
6. Unlisted/deleted/year-1900 metadata is handled without weakening age policy.
7. Package IDs and versions normalize exactly as required by NuGet clients and
   OSV identity matching.
8. `check nuget:<id>@<version>` is registry-backed and `eval` supports NuGet.
9. Live/local OSV use ecosystem `NuGet`; local exact and observed range shapes
   work without request-path OSV calls.
10. Unit, route, and real-client tests cover dependency restore, fresh/locked
    installs, blocked versions, prereleases, redirect, and proxy modes.
11. CI executes real .NET coverage with a pinned supported SDK.
12. Docs accurately scope restore support and unsupported search/publish flows.
13. Formatting, tests, clippy, config validation, and diff checks pass.
14. All milestones are checked and independently committed.

## Milestone Checklist and Checkpoint Protocol

For every completed milestone:

1. Run the milestone verification.
2. Mark its checkbox `[x]`.
3. Add a dated status note with exact commands and results.
4. Commit code, tests, docs, and status update together.
5. Record and report the commit hash before continuing.

- [x] Milestone 0: NuGet V3 research and restore contract
- [x] Milestone 1: NuGet ecosystem, config, OSV, and CLI foundations
- [x] Milestone 2: Service index and registration filtering
- [x] Milestone 3: Flat-container and package enforcement
- [x] Milestone 4: Real .NET restore, docs, and regression

## Milestone 0: NuGet V3 Research and Restore Contract

Problem:

- NuGet V3 is a service graph, and over-advertising passthrough resources can
  create policy bypasses even when package downloads are protected.

Desired behavior:

- Define the exact resource types/versions exposed, their proxy URL graph, and
  how restore works without search or publishing. Record inline/paged
  registration handling, conditional requests, unlisted semantics, timestamp
  selection, version normalization, and response-status mapping.

Acceptance criteria:

- Official docs and real nuget.org responses were inspected.
- The service index advertises no upstream URL that can satisfy a restore while
  bypassing policy.
- Fixtures reflect observed inline and paged shapes where applicable.
- Milestone status is marked done and committed.

Likely files:

- `docs/internal/goal-11-nuget-dotnet-support.md`
- optional focused fixtures

Verification:

```bash
git diff --check
```

Status (2026-07-09): Complete. Inspected the Microsoft Learn service-index,
registration-base-url, package-base-address, and package-versioning references,
plus nuget.org's documented V3 index and observed `Newtonsoft.Json` restore
graph. The proxy will advertise only `RegistrationsBaseUrl/3.6.0` at
`/nuget/v3/registration-semver2/` and `PackageBaseAddress/3.0.0` at
`/nuget/v3/flatcontainer/`; the service index is `/nuget/v3/index.json`.
Registration index/page/leaf `@id`, `catalogEntry`, and `packageContent` links
are rewritten to those surfaces. Flat-container index, `.nupkg`, and `.nuspec`
use lower-invariant package IDs and normalized, lowercased versions. NuGet
normalization removes leading zeroes, a zero fourth component, and SemVer 2
build metadata; prerelease labels compare case-insensitively. Registration
`published` is the age timestamp. nuget.org's `1900-01-01T00:00:00Z` unlisted
sentinel is treated as missing publication time, never as an old allowed
release. Flat-container discovery fetches one registration index and at most
one page per version-list page (with a fixed bound) before policy evaluation;
unsupported registration shapes fail closed. A policy denial is `403`; missing
resources are `404`; malformed/upstream metadata is a deterministic `502`.
Verified with `git diff --check` (pass).

## Milestone 1: NuGet Ecosystem, Config, OSV, and CLI Foundations

Problem:

- Shared types and storage cannot represent NuGet package identities or version
  semantics.

Desired behavior:

- Add strict nuget.org upstream config, case-insensitive ID normalization,
  NuGet-compatible versions, registry-backed CLI lookup boundaries, and live/
  local OSV support using actual NuGet advisory shapes.

Acceptance criteria:

- ID normalization is consistent across URLs, policy entries, SQLite lookup,
  and OSV queries.
- Version parsing/comparison covers normalized versions, prereleases, and
  SemVer 2 cases used by clients and OSV.
- Local sync state is independent and makes no request-path OSV calls.
- npm/PyPI regressions pass.
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

Status (2026-07-09): Complete. Flat-container indexes are derived from filtered
registration leaves and direct `.nupkg`/`.nuspec` requests re-evaluate policy
before redirect or streaming delivery. Verified with focused NuGet unit tests
and real-client redirect/proxy restore tests.

Status (2026-07-09): Complete. The proxy service index advertises only owned
registration and flat-container resources. Registration roots hydrate bounded
upstream pages, filter every leaf by publication time and policy, recompute
counts, and rewrite package-content and registration URLs. Proxy-owned root,
page, and leaf routes filter their returned document before serialization.
Verified with `cargo test nuget::tests`, `cargo fmt --check`, `cargo clippy
--all-targets --all-features -- -D warnings`, and `git diff --check` (pass).

Status (2026-07-09): Complete. Added the `NuGet` OSV ecosystem, strict
`upstreams.nuget.service_index_url` configuration (defaulting to nuget.org),
case-insensitive package ID normalization, and NuGet V3 version normalization
for CLI identities, policy lists, URLs, and local storage. `check
nuget:<id>@<version>` resolves a registration leaf and uses its publication
timestamp; `eval` accepts the same identity. Local malicious sync now imports
the canonical NuGet dump alongside npm and PyPI. Verified with `cargo test
artifact::tests`, `cargo test config::tests`, `cargo test cli::tests`, `cargo
test malicious::tests`, `cargo fmt --check`, and `git diff --check` (all pass).

## Milestone 2: Service Index and Registration Filtering

Problem:

- NuGet clients discover dynamically linked resources, and registration
  documents may inline leaves or point to pages and package content.

Desired behavior:

- Serve a minimal proxy-owned service index and filter/rewrite all supported
  registration shapes. Preserve required metadata and forward-compatible fields
  while ensuring every traversable restore URL stays behind the proxy.

Acceptance criteria:

- Inline and paged registration structures are handled or unsupported shapes
  fail closed with an explicit error.
- Blocked/too-new versions are absent and counts/bounds remain consistent.
- `published` drives age policy; unlisted sentinel behavior is explicitly tested.
- `@id`, page, leaf, registration, and `packageContent` URLs do not leak an
  upstream bypass.
- Work is bounded for large packages and upstream failures are deterministic.
- Milestone status is marked done and committed.

Likely files:

- `src/nuget.rs`
- `src/server.rs`
- `src/lib.rs`

Verification:

```bash
cargo test nuget
cargo test server
cargo fmt --check
```

## Milestone 3: Flat Container and Package Enforcement

Problem:

- Restore can enumerate and download through PackageBaseAddress independently
  of registration links, including exact versions from lock state.

Desired behavior:

- Filter flat-container `index.json` using authoritative registration metadata,
  protect `.nuspec` and `.nupkg` requests with canonical policy context, and
  deliver allowed packages through shared redirect/proxy behavior.

Acceptance criteria:

- Direct blocked `.nupkg` and `.nuspec` requests are terminal and do not fetch
  large package bytes.
- Allowed packages and manifests satisfy real NuGet clients.
- Package ID/version confusion, normalization aliases, and traversal are tested.
- Redirect/proxy bytes and useful headers match existing artifact invariants.
- Correlation request fan-out is bounded and tested.
- Milestone status is marked done and committed.

Likely files:

- NuGet adapter module
- `src/artifacts.rs`
- `src/server.rs`

Verification:

```bash
cargo test nuget
cargo test artifacts
cargo test server
cargo fmt --check
```

## Milestone 4: Real .NET Restore, Docs, and Regression

Problem:

- JSON fixture tests do not prove compatibility with the NuGet resolver's
  resource selection, dependency traversal, lock files, and package validation.

Desired behavior:

- Run hermetic real `dotnet restore` tests against local fixture resources with
  at least one dependency edge. Install a pinned supported SDK in CI and make
  missing client coverage a visible failure rather than a skip.

Acceptance criteria:

- Real-client tests cover fresh and locked restore, dependency traversal, newly
  blocked locked version, prerelease handling, redirect, and proxy modes.
- Tests contact neither nuget.org nor OSV.
- CI runs the test with an explicit SDK version.
- README, client/configuration/registry/architecture/malicious docs, product
  spec, and milestones consistently describe NuGet restore support and limits.
- Full regression passes and the status update is committed.

Likely files:

- focused NuGet integration test and fixtures
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

Status (2026-07-09): Complete. CI pins .NET SDK 8.0.128. Hermetic actual-listener
tests use a local V3 upstream and only the proxy source, covering dependency
restore, redirect and proxy delivery, fresh block, locked newly-blocked restore,
and an explicit prerelease. Final verification commands are recorded in the
checkpoint commit.

## Final Response Required

Report:

- target state achieved or any gaps;
- milestone commits in order;
- files changed;
- exact verification results, including real `dotnet restore` execution;
- supported V3 resources and remaining interoperability/performance risks;
- confirmation that no merge, version bump, tag, release, publishing/search
  implementation, or edits to another ecosystem goal prompt were made.
