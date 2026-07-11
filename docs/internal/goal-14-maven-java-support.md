# Goal: Maven Central Support for Maven and Gradle

Work in `/Users/smarzola/projects/osv-proxy` on branch
`feat/maven-java-support`, starting from `main` commit `2e6d22d`.

Add production-quality, read-only Maven Repository Layout support backed by
Maven Central. Maven and Gradle must resolve only policy-allowed releases and
download allowed coordinate-scoped files through the existing redirect or
proxy delivery modes.

Source of truth: this prompt, the official Maven Repository Layout and mirror
documentation, the official Gradle Maven-repository documentation, the OSV
Maven ecosystem implementation, observed Maven Central response behavior, and
the repository's existing package-adapter invariants.

## Target State

When this goal is complete:

- Maven and Gradle can use `/maven/` as their only remote Maven repository for
  supported Maven Central release workflows.
- Artifact-level `maven-metadata.xml` excludes releases denied by policy and
  derives its advertised latest/release versions from the retained set.
- Every coordinate-scoped POM, JAR, Gradle module, classifier, signature, and
  checksum request is independently mapped to one canonical Maven package,
  enriched with a trustworthy publication time, and policy-checked before
  artifact bytes are fetched or redirected.
- Maven coordinates use OSV's canonical `Maven` ecosystem and
  `groupId:artifactId` package names, with Maven-compatible version ordering for
  local OSV ranges.
- `check maven:<groupId>:<artifactId>@<version>` uses live registry metadata,
  local OSV sync includes Maven, and operator documentation covers secure Maven
  and Gradle client configuration.

## Current-State Evidence

Verified before this prompt was written:

- `src/artifact.rs::Ecosystem` supports npm, PyPI, Go, crates.io, NuGet, and
  RubyGems, but not Maven.
- `src/config.rs::UpstreamsConfig` has one upstream section per current adapter
  and no Maven repository URL.
- `src/malicious.rs::sync_osv` synchronizes six ecosystems and
  `range_matches_artifact` deliberately selects ecosystem-specific comparators.
- `src/server.rs` owns routing and composes dedicated adapters with the shared
  policy checker and artifact delivery modes.
- `tests/package_manager_e2e.rs` exercises real npm, Python, Cargo, Go, .NET,
  and Bundler clients against hermetic registries and the live Axum listener.
- `.github/workflows/ci.yml` pins the non-Java client toolchains but does not
  provision pinned Java, Maven, or Gradle clients.
- Maven's current repository layout maps group path, artifact, version,
  classifier, and extension deterministically. Maven can force all repositories
  through one mirror with `mirrorOf=*`; Gradle consumes Maven repositories and
  may prefer Gradle Module Metadata before POM metadata.
- Maven Central release POM responses expose `Last-Modified`, validators, and
  checksums. The adapter must verify this behavior hermetically and use the
  version POM as the publication-time authority without fetching denied
  artifact bytes.
- OSV publishes a canonical `Maven` dump and its reference ecosystem helper
  implements Maven-specific ordering rather than SemVer ordering.

Unknowns that may affect implementation details, but not the target state:

- Maven and Gradle checksum negotiation differs by client version; hermetic
  client traces must determine which filtered-metadata checksum sidecars are
  required.
- Some valid Central artifacts use uncommon extensions or classifiers. Routing
  must validate Maven-layout paths without assuming only `.pom` and `.jar`.

## Constraints And Non-Goals

Follow `AGENTS.md`; correctness and package-install-path performance are
mandatory.

- Keep Maven parsing, metadata access, version semantics, response generation,
  and error mapping in a dedicated adapter. Keep shared policy and delivery
  logic ecosystem-neutral.
- Use `Maven` for OSV, `maven` for user-facing identities, and the exact
  case-sensitive `groupId:artifactId` as the package name.
- Scope the first release to immutable Maven Central releases using Maven
  Repository Layout. Do not support snapshots, publishing, deletes, search,
  authentication, private repositories, repository aggregation, or hosting.
- Permit only read-only repository operations and strict Maven-layout paths.
  Do not create a general-purpose upstream HTTP proxy.
- Preserve upstream coordinate-scoped bytes exactly. Rewritten metadata owns
  its validators and checksum sidecars.
- Batch policy evaluation and bound concurrent upstream enrichment. Do not add
  an in-process metadata cache or contact OSV from local request paths.
- Recheck policy before every coordinate-scoped delivery. A blocked request
  must not contact the upstream artifact-byte endpoint.
- Treat missing releases as `404`, policy denials as structured `403`, and
  malformed metadata, ambiguous paths, or non-not-found upstream failures as
  deterministic `502` responses.
- Preserve all existing adapters and tests.
- Do not bump versions, push, open a PR, tag, publish, or release.
- Preserve unrelated user changes and work safely in a dirty worktree.

## Authorization And Decisions

This goal authorizes repository inspection, in-scope local edits, focused
Conventional Commits, branch-local checkpoints, separate Codex app reviewer
threads, and relevant non-destructive verification.

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

Decision: expose the repository at `/maven/`. The remaining request path follows
Maven Repository Layout and the default upstream is
`https://repo.maven.apache.org/maven2`.

Decision: publication time comes from the release POM's upstream
`Last-Modified`. Missing or invalid timestamps follow
`policy.missing_publish_time`; a missing POM means the coordinate cannot be
evaluated and is not installable. Metadata enrichment may issue bounded POM
metadata requests, but denied artifact bytes must never be fetched.

Decision: artifact-level metadata is a resolver gate and must be filtered.
Group-level plugin-prefix metadata may be passed through unchanged because it
does not identify a version; version-level snapshot metadata is unsupported.

Decision: all files under a validated release coordinate share the package
policy identity `Maven:<groupId>:<artifactId>@<version>`. Classifier and
extension distinguish files but do not create different OSV package versions.

Decision: the proxy controls remote fetches, not artifacts already present in a
client's local cache. E2E denial tests must use clean Maven/Gradle caches.

## Success Criteria

The goal is complete only when:

1. Real pinned Maven and Gradle clients resolve fresh transitive dependency
   graphs using only `/maven/`, in both redirect and proxy artifact modes.
2. Artifact-level metadata preserves allowed releases, excludes blocked,
   vulnerable, malicious, too-new, missing, and unevaluable releases, and owns
   consistent latest/release values, validators, and checksum sidecars.
3. Exact release requests validate Maven-layout coordinates, use POM publication
   metadata, recheck policy, and protect POMs, JARs, Gradle modules, classifiers,
   signatures, and checksums without altering allowed bytes.
4. Direct bypass attempts cannot fetch or redirect denied artifact bytes;
   denials are structured `403`, missing coordinates are `404`, and invalid or
   upstream failures are deterministic `502`.
5. Maven version comparison matches representative OSV/Maven ordering,
   including qualifiers and numeric transitions, and local OSV exact/range
   evaluation works without request-path network calls.
6. Live/local OSV use `Maven`; local sync includes its dump; CLI `check` and
   `eval` support `maven:groupId:artifactId@version` identities.
7. Hermetic tests cover transitive dependencies, a BOM or plugin, dynamic
   version selection, Gradle Module Metadata, redirect, proxy, minimum age,
   blocklist/OSV denial, direct bypass, clean-cache pinned resolution, and
   upstream errors.
8. CI pins Java, Maven, and Gradle and executes real-client coverage without
   silently skipping it.
9. README, architecture, configuration, client, behavior, OSV-data, product,
   and milestone docs accurately state the supported Maven/Gradle surface,
   secure sole-repository configuration, cache limitation, and v1 non-goals.
10. Every milestone is checked off with exact verification evidence, a clean
    adversarial review, and a focused Conventional Commit.
11. Final formatting, tests, clippy, config validation, diff checks, and an
    independent full-goal audit pass.

## Milestones

- [x] Milestone 1: Maven identity, configuration, version semantics, OSV, and CLI
- [x] Milestone 2: Policy-filtered Maven metadata and response semantics
- [x] Milestone 3: Protected coordinate-scoped delivery and routing
- [x] Milestone 4: Real Maven/Gradle workflows, CI, docs, and full regression

### Checkpoint Protocol

At the end of each milestone:

1. Satisfy its acceptance criteria.
2. Run its verification commands and inspect the results.
3. Freeze main-thread writes and obtain adversarial read-only review in the
   persistent same-directory Codex app reviewer thread. Repair and re-review
   until no blocking findings remain.
4. Mark its checkbox `[x]` and add a dated status note under that milestone with
   the outcome, exact commands, results, and review disposition.
5. Commit the implementation, tests, docs, and this prompt update together with
   a focused Conventional Commit.
6. Report the resulting commit hash before starting the next milestone.

If verification fails, leave the milestone unchecked and do not make its
checkpoint commit. Diagnose and repair in-scope failures. A commit cannot
contain its own final hash, so report the hash after committing.

## Milestone 1: Maven Foundations

Why this matters:

- Shared identity, OSV storage, Maven ordering, and registry-backed lookup must
  be correct before HTTP routes can enforce policy.

Acceptance criteria:

- Maven identities/configuration normalize consistently across CLI, policy
  lists, SQLite, OSV queries, and upstream URLs.
- Maven version ordering matches the OSV reference behavior for representative
  releases, aliases, qualifiers, numeric transitions, and invalid input.
- Local OSV sync/readiness includes Maven, and local ECOSYSTEM ranges evaluate
  with Maven ordering.
- Registry-backed `check` derives one canonical artifact from an upstream POM
  metadata response and reports deterministic missing/upstream errors.

Likely touchpoints (non-exhaustive):

- `src/artifact.rs`, `src/config.rs`, `src/maven.rs`, `src/malicious.rs`
- `src/cli.rs`, `src/lib.rs`, `examples/basic/osv-proxy.yaml`

Verification:

```bash
cargo test artifact::tests
cargo test maven::tests
cargo test malicious::tests
cargo test cli::tests
cargo run -- config validate --config examples/basic/osv-proxy.yaml
```

Status: Completed 2026-07-11. Added canonical Maven identity/configuration,
bounded release-POM metadata lookup, Maven-compatible version ordering, local
OSV dump/range support, and registry-backed CLI evaluation. Verification passed:
`cargo test artifact::tests` (8), `cargo test maven::tests` (9),
`cargo test malicious::tests` (52), `cargo test cli::tests` (16),
`cargo run -- config validate --config examples/basic/osv-proxy.yaml`, and
`git diff --check`. Adversarial review required one repair round for bounded POM
reads, malformed timestamp policy handling, and comparator coverage; re-review
reported no findings and no blocking findings remain.

## Milestone 2: Filtered Resolver Metadata

Why this matters:

- Maven/Gradle dynamic resolution must not select a denied release and then fail
  late at artifact download when an older allowed release exists.

Acceptance criteria:

- Artifact-level `maven-metadata.xml` is strictly parsed, bounded, enriched from
  release POM metadata with bounded concurrency, and batch policy-evaluated.
- Denied or missing releases are omitted; invalid metadata and non-not-found
  enrichment failures fail closed.
- Retained ordering is deterministic, latest/release are derived from allowed
  versions, and filtered bodies own ETag/conditional and checksum-sidecar
  semantics.
- Group plugin metadata pass-through is bounded and version-level snapshot
  metadata is rejected as unsupported.

Likely touchpoints (non-exhaustive):

- `src/maven.rs`, `src/response.rs`, `src/server.rs`

Verification:

```bash
cargo test maven::tests
cargo test server::tests
```

Status: Completed 2026-07-11. Added bounded artifact/group metadata fetching,
strict Maven XML shape validation, at-most-16 concurrent POM enrichment,
single-batch OSV evaluation, filtering for missing and policy-denied releases,
derived latest/release values, proxy-owned ETag/conditional handling, and
MD5/SHA-1/SHA-256/SHA-512 sidecars. Verification passed:
`cargo test maven::tests` (16), `cargo test server::tests` (29), and
`git diff --check`. Adversarial review required two repair rounds for the real
rootless Maven Central plugin-prefix metadata shape, weak entity-tag comparison,
and preserving `404`/`502` responses under wildcard conditionals. Final
re-review reported no findings and no blocking findings remain.

## Milestone 3: Protected Release Delivery

Why this matters:

- Direct coordinate URLs must not bypass discovery filtering or contact denied
  artifact-byte endpoints.

Acceptance criteria:

- Strict route parsing reconstructs one GAV from the directory layout and
  validates the filename without guessing classifier boundaries.
- Every supported coordinate-scoped file resolves its release POM metadata,
  rechecks policy, and then uses redirect or proxy delivery unchanged.
- Unsupported methods, traversal/encoding tricks, malformed paths, missing
  files, policy denials, and upstream errors map deterministically.
- Tests prove blocked direct requests do not contact the artifact-byte listener.

Likely touchpoints (non-exhaustive):

- `src/maven.rs`, `src/server.rs`, `src/artifacts.rs`

Verification:

```bash
cargo test maven::tests
cargo test server::tests
cargo test e2e
```

Status: Completed 2026-07-11. Added strict Maven release-path reconstruction,
protected POM/JAR/module/classifier/signature/checksum delivery, HEAD-only POM
policy preflight, exact redirect existence checks, streaming proxy GET/HEAD,
and deterministic `403`/`404`/`502` responses. Verification passed:
`cargo test maven::tests` (22), `cargo test server::tests` (31),
`cargo test artifacts::tests` (4), `cargo test e2e` (6), and
`git diff --check`. Adversarial review required one repair round to prevent
blocked direct POM requests from fetching POM bodies and to prevent non-POM
files from inheriting POM hashes. Re-review reported no findings and no
blocking findings remain.

## Milestone 4: Maven/Gradle Integration and Documentation

Why this matters:

- Unit routes are insufficient proof that real dependency resolvers use only
  the protected surface and remain compatible with rewritten metadata.

Acceptance criteria:

- Hermetic pinned Maven and Gradle E2Es cover the success, denial, transitive,
  dynamic, metadata, redirect/proxy, and clean-cache cases in the success
  criteria.
- CI provisions pinned Java/Maven/Gradle clients and cannot silently skip their
  tests.
- Operator and architecture docs explain supported behavior, secure Maven and
  Gradle configuration, local-cache limitations, and v1 non-goals.
- All pre-existing adapters and the full regression suite remain green.

Likely touchpoints (non-exhaustive):

- `tests/package_manager_e2e.rs`, `.github/workflows/ci.yml`
- `README.md`, `docs/*.md`, `examples/basic/osv-proxy.yaml`

Verification:

```bash
cargo test --test package_manager_e2e
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
git diff --check main...HEAD
```

Status: Completed 2026-07-11. Added hermetic Maven 3.9.11 and Gradle 8.14.3
workflows under Temurin 21.0.7+6, covering redirect and proxy delivery,
transitive graphs, dynamic filtering, Gradle Module Metadata, fresh denials,
and clean-cache pinned/locked denial transitions. CI pins and verifies the
client toolchain, and the public docs now cover the Maven surface, sole-proxy
configuration, cache limits, and non-goals.

Verification: `cargo test --locked --test package_manager_e2e` passed 14 tests;
`cargo test --locked` passed 251 unit tests, 14 real-client E2Es, and doc tests;
`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml`,
and `git diff --check` passed. The pinned Maven archive SHA-512 was checked
against the downloaded official archive. Adversarial review found an invalid
bare-checksum CI invocation and inaccurate metadata-validator wording; both
were repaired, and re-review reported CLEAN with no blocking findings.

## Final Verification

Run from `/Users/smarzola/projects/osv-proxy`:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- config validate --config examples/basic/osv-proxy.yaml
git diff --check main...HEAD
git status --short
```

Then create a fresh same-directory Codex app reviewer thread and audit the full
branch against every target-state bullet and success criterion. Repair and
re-review until no blocking findings remain, then rerun final verification.

Do not treat a checkbox or commit as proof that a command passed. Inspect
failures and fix in-scope regressions rather than weakening tests. For an
unrelated pre-existing failure, record the command, result summary, and evidence
that this goal did not cause it.

## Resume Protocol

On a resumed session, first read this prompt, `AGENTS.md`, `git status`, milestone
status notes, and recent commits. Verify completed checkpoints and continue from
the first unchecked milestone without redoing completed work. New evidence may
refine implementation details but must not silently weaken the target state or
success criteria.

## Final Report

Lead with `Achieved` or `Not achieved`, then report:

- target state and success criteria status;
- branch and milestone checkpoint commits;
- files changed;
- exact verification commands and results;
- reviewer rounds and dispositions;
- residual risks, follow-ups, or unauthorized external delivery steps.
