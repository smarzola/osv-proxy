# Goal: Eliminate High-Severity Audit Findings

Work in `/Users/smarzola/projects/osv-proxy` on branch
`fix/high-severity-audit-findings`, starting from
`f97583049ec6b3c590045e6056fb586a2ecd18dd` on `main`.

Eliminate every high-severity finding in
`docs/internal/audit-2026-07-11.md` without weakening the proxy's fail-closed
policy, supported registry behavior, deterministic responses, or install-path
performance. Deliver the verified changes as focused Conventional Commits and
open the user-authorized draft pull request after the independent final audit.

Source of truth: the seven findings in the audit's
`## High-severity findings` section (`SEC-01` through `REL-01`).

## Target State

When this goal is complete:

- locked runtime dependencies have no known high/critical RustSec advisories;
- every upstream metadata/API/archive body is bounded while it is read, and
  registry behavior remains compatible with supported clients;
- proxy-mode artifact fetches cannot reach untrusted non-public network
  destinations or follow unvalidated redirects, while explicitly configured
  local/private test or operator upstreams remain usable;
- request handling reuses registry/artifact HTTP clients across requests;
- local SQLite evaluation, Maven XML parsing, and material local OSV
  range/version CPU work do not run on Tokio workers, and batch range work
  scales by package/range rather than version times range;
- failure syncing one ecosystem does not prevent attempts for the remaining
  ecosystems, background failures retry sooner than the normal interval, and
  overlapping sync runs are prevented;
- the audit records the remediation evidence and no high-severity item remains
  open.

## Current-State Evidence

Verified before implementation:

- `cargo audit` against `Cargo.lock` reports `RUSTSEC-2026-0194` and
  `RUSTSEC-2026-0195` for directly used `quick-xml 0.38.4`.
- `src/artifacts.rs::ArtifactDeliveryClient::deliver` accepts metadata-derived
  URLs without an egress or redirect policy.
- npm, PyPI, NuGet, Go, and OSV HTTP paths decode bodies without a streamed
  ceiling; Maven and RubyGems already contain reusable bounded-read patterns.
- `src/server.rs::route_http_request_with_accept_and_headers` constructs all
  ecosystem clients per request while `AppState` retains only config/checker.
- `SqliteMaliciousChecker` opens and queries synchronous Rusqlite connections
  directly inside async trait methods; `check_many_with_connection` reloads
  package ranges for each unique version and queries each range's events.
- `sync_osv` returns on the first ecosystem error, and the background loop then
  sleeps the full configured interval.
- Baseline verification: format and Clippy pass; 251 unit tests pass; 12 of 14
  package-manager e2e tests pass locally, with Maven and Gradle unable to start
  because those CLIs are not installed on this machine.

Unknowns that may refine implementation details without weakening the target:

- exact safe response ceilings per ecosystem, derived from protocol fixtures,
  realistic registry payloads, and existing adapter limits;
- whether Reqwest's public resolver hooks are sufficient for centralized
  post-resolution private-address rejection or require an equivalent client
  boundary.

## Constraints And Non-Goals

Follow `AGENTS.md` and preserve correctness and low latency in the package
install path.

- Keep changes limited to the seven high-severity findings, their tests,
  necessary config/docs, CI gates, and this goal/audit status.
- Preserve all seven supported ecosystems, redirect and proxy artifact modes,
  public configuration compatibility, structured policy decisions, local
  SQLite generation semantics, and existing CLI commands.
- Local/private upstreams explicitly configured by operators and hermetic tests
  must remain possible; metadata may not silently expand that trust boundary.
- Do not add authentication, health endpoints, metadata caching, S3 caching,
  or unrelated medium/low audit work.
- Do not release or merge. The user authorized branch push and a draft PR only.
- Preserve unrelated user changes; the audit file created immediately before
  this goal is in scope and belongs in the branch.

## Authorization And Decisions

This goal authorizes repository inspection, in-scope edits, non-destructive
verification, typed branch work, Conventional Commit checkpoints, reviewer
subagents, pushing this branch, and opening the requested draft pull request.

Require confirmation before destructive actions, merging, releasing,
publishing artifacts, changing secrets/permissions, or expanding beyond the
high-severity remediation. Continue through routine implementation choices
using repository evidence. Ask only when ambiguity materially changes public
compatibility, data semantics, security posture, or authorization.

Before declaring a blocker, exhaust safe in-scope alternatives and record the
evidence. Do not weaken tests or silently narrow success criteria.

## Success Criteria

The goal is complete only when:

1. `cargo audit` reports no high or critical advisory for the locked runtime
   dependency graph, and CI/tag validation enforce the dependency gate.
2. All upstream body readers enforce documented byte ceilings during streaming
   (not only after allocation), with oversize tests for declared and chunked
   bodies; large OSV archives use bounded streaming storage rather than a
   whole-body in-memory allocation.
3. Artifact proxy egress validates schemes, destinations after DNS resolution,
   and redirects; untrusted loopback/private/link-local destinations fail
   before contact, while explicitly configured private origins work.
4. Application state owns reusable ecosystem and artifact clients; request
   routing does not construct unused Reqwest clients.
5. Local SQLite checks, Maven XML parsing, and material local OSV range/version
   evaluation execute behind bounded blocking/concurrency boundaries with
   deterministic error propagation; reads are opened/reused safely and batch
   range query-count complexity is package/range based.
6. OSV sync attempts every ecosystem independently, records each failure,
   preserves successful generations, returns an aggregate outcome, and applies
   bounded retry/backoff behavior in background mode.
7. Audit text marks all seven high findings resolved with commit/test evidence
   while retaining the original finding descriptions for history.
8. Existing unit, integration, config, formatting, and lint behavior passes;
   unavailable Maven/Gradle local prerequisites are reported, not disguised.
9. Persistent milestone review and a fresh independent final audit report no
   blocking findings.
10. Every milestone is checked off with verification evidence and a focused
    Conventional Commit; the final branch is pushed and a draft PR targets
    `main`.

## Milestones

- [x] Milestone 1: Harden dependencies and bound upstream bodies.
- [ ] Milestone 2: Enforce artifact egress and redirect safety.
- [ ] Milestone 3: Reuse clients and make local policy evaluation async-safe and
  package-batched.
- [ ] Milestone 4: Isolate ecosystem sync failures and implement background
  retry behavior.

### Checkpoint Protocol

For each milestone: satisfy acceptance criteria, run and inspect the narrow
verification, update its checkbox and dated status below, complete adversarial
review/repair rounds, then commit implementation, tests, docs, and goal status
together with a focused Conventional Commit. Report the resulting hash before
starting the next milestone. Do not checkpoint failed or unreviewed work.

## Milestone 1: Harden Dependencies And Bound Upstream Bodies

Why this matters: it removes the known reachable XML parser vulnerabilities and
prevents metadata/API/archive memory exhaustion.

Acceptance criteria:

- `quick-xml` is upgraded to a non-vulnerable compatible version and Maven XML
  parsing tests cover adversarial namespace/attribute shapes within limits.
- One bounded streaming response mechanism protects every registry metadata,
  live OSV response, and OSV dump fetch path with clear ecosystem limits and
  structured errors; OSV archives stream to bounded temporary storage instead
  of being accumulated as a single in-memory HTTP body.
- CI and release validation run Clippy and RustSec audit checks.

Likely touchpoints: `Cargo.toml`, `Cargo.lock`, HTTP adapter modules,
`src/malicious.rs`, `.github/workflows/{ci,release}.yml`.

Narrow verification:

```bash
cargo test --locked --lib
cargo clippy --all-targets --all-features -- -D warnings
cargo audit --file Cargo.lock
```

Status: Completed 2026-07-11 after two adversarial review rounds. The first
round found an unsafe buffering default on the public archive trait and missing
tempfile-specific oversize tests; both were repaired and the re-review was
clean. `quick-xml` was upgraded to 0.41.0; `src/http_body.rs` became the shared streamed
bound for registry/OSV metadata and temporary-file archive downloads; expanded
ZIP limits and CI/release Clippy/RustSec gates were added. Verification:
`cargo fmt --check` passed; `cargo test --locked --lib` passed 258 tests;
focused body, archive, and adversarial XML tests passed;
`cargo clippy --all-targets --all-features -- -D warnings` passed; RustSec
scanned 222 locked dependencies with no vulnerability findings; `git diff
--check` passed.

## Milestone 2: Enforce Artifact Egress And Redirect Safety

Why this matters: proxy delivery must not turn registry metadata into access to
untrusted internal services.

Acceptance criteria:

- artifact URLs use a centralized typed validation/egress path;
- only supported schemes are accepted, redirects are disabled or revalidated,
  and DNS resolution cannot select forbidden non-public addresses unless the
  hostname/origin is explicitly trusted by configured upstreams;
- regression tests prove blocked literal IPv4/IPv6, hostname/private DNS, and
  redirect cases are never contacted, plus configured local upstream success.

Likely touchpoints: `src/artifacts.rs`, shared HTTP client construction,
`src/config.rs`, ecosystem artifact tests, security/operator docs.

Narrow verification:

```bash
cargo test --locked artifacts
cargo test --locked --lib proxy
cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml
```

Status: Not started.

## Milestone 3: Reuse Clients And Make Local Evaluation Async-Safe

Why this matters: the install path must reuse connection pools and prevent
synchronous SQLite/range work from stalling unrelated requests.

Acceptance criteria:

- `AppState` owns and routes through shared clients without constructing all
  clients per request;
- SQLite work, Maven XML deserialization, and material local OSV range/version
  evaluation run through bounded blocking boundaries with deterministic error
  propagation, with regression evidence that request futures yield while that
  work is occupied;
- local batch evaluation loads package ranges/events once and evaluates all
  requested versions without N+1 range-event queries;
- tests or instrumentation assert client reuse and bounded query behavior.

Likely touchpoints: `src/server.rs`, adapter client types,
`src/malicious.rs`, local-mode tests.

Narrow verification:

```bash
cargo test --locked --lib server::tests
cargo test --locked --lib malicious::tests
cargo clippy --all-targets --all-features -- -D warnings
```

Status: Not started.

## Milestone 4: Isolate Sync Failures And Retry Safely

Why this matters: one registry-data failure must not stale every later
ecosystem for the full normal interval.

Acceptance criteria:

- one sync run attempts all seven ecosystems and reports per-ecosystem success
  or failure without exposing partial generations;
- concurrent explicit/background sync entry is serialized or rejected so
  generation work for the same store cannot overlap;
- background mode retries failures with bounded exponential backoff and jitter
  or an equivalently bounded deterministic test seam, while successful normal
  cycles respect `sync_interval`;
- tests cover an early ecosystem failure followed by later successes, aggregate
  reporting, preserved generations, and retry scheduling.

Likely touchpoints: `src/malicious.rs`, `src/server.rs`, CLI report model,
sync tests and docs.

Narrow verification:

```bash
cargo test --locked --lib sync
cargo test --locked --lib background
cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml
```

Status: Not started.

## Final Verification

Run from `/Users/smarzola/projects/osv-proxy`:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --lib
cargo test --locked --test package_manager_e2e
cargo run --locked -- config validate --config examples/basic/osv-proxy.yaml
cargo audit --file Cargo.lock
git diff --check main...HEAD
```

Run the package-manager e2e suite with normal host access. If `mvn` and
`gradle` remain unavailable, record those two prerequisite failures and prove
the remaining 12 cases pass, as on the baseline.

## Resume Protocol

On resume, read this goal, `AGENTS.md`, git status, milestone notes, and recent
commits. Verify completed checkpoints and continue from the first unchecked
milestone. New evidence may refine implementation details but may not weaken
the target state or criteria.

## Final Report

Lead with `Achieved` or `Not achieved` and include target/success-criterion
status, milestone commits, files changed, exact verification results, reviewer
rounds and dispositions, residual risks, branch/push state, and the draft PR
URL. Do not claim release or merge completion.
