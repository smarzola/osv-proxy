# Goal: npm Metadata Filtering and Redirect Artifacts

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Implement npm support for phase one: fetch upstream npm metadata, evaluate every version through the shared policy engine, remove blocked versions, rewrite allowed tarball URLs to `osv-proxy` URLs, recompute `dist-tags`, and recheck policy on tarball redirect routes.

This phase supports naive OSV mode and redirect artifacts only. Do not add metadata cache, local malicious storage, proxy streaming, or S3 cache behavior.

## Repository Rules

- Keep npm-specific parsing and URL logic in the npm adapter or route module.
- Keep the core policy model ecosystem-neutral.
- Do not add an in-process metadata cache.
- Preserve the invariant that policy is checked during metadata generation and checked again during artifact serving.
- Do not revert changes made by other workers. You are not alone in this codebase.

## Target State

- `GET /npm/{package}` and `GET /npm/@{scope}/{package}` return filtered npm metadata.
- Allowed versions keep integrity and shasum values.
- Allowed versions have `dist.tarball` rewritten to public `osv-proxy` npm artifact URLs.
- Blocked versions are absent from metadata.
- `dist-tags` never point to removed versions.
- npm tarball routes re-evaluate policy and return either structured 403 JSON or a 302 redirect to upstream.

## Current State

This worker may receive the repo after the core scaffold exists. If core files are missing, stop and report that Goal 01 is required first.

## Definition of Done

1. npm metadata routes are implemented and covered by tests.
2. npm artifact redirect routes are implemented and covered by tests.
3. Tests use local mocked upstream responses, not the real npm registry.
4. Policy is checked both when filtering metadata and when serving tarball redirects.
5. `cargo test npm` passes, and full `cargo test` passes.

## Milestone Checklist

- [x] npm route registration and upstream fetch
- [x] npm metadata filtering and URL rewriting
- [x] npm artifact redirect gate
- [x] npm adapter tests

Status note, 2026-07-05: Completed phase-one npm adapter support with mocked upstream tests. Verification commands run: `cargo fmt`, `cargo test npm`, `cargo test npm_metadata`, `cargo test npm_artifact`, `cargo test`, `cargo fmt --check`, `git diff --check`. Commit: included in this checkpoint commit; final hash reported by `git log`.

## Checkpoint Protocol

When a milestone is complete:

1. Run the milestone's verification commands.
2. Update this file by changing the milestone checkbox from `[ ]` to `[x]`.
3. Add a short status note with the date, exact commands run, and commit hash if available.
4. Commit the code, tests, docs, and status-note update with a focused commit message if committing is available in your workspace.
5. Report the commit hash or state that commits are unavailable before starting the next milestone.

## Milestone 1: npm Route Registration and Upstream Fetch

Problem: npm clients need registry-compatible metadata and tarball paths.

Desired behavior: the server accepts documented npm metadata and artifact routes.

Acceptance criteria:

- Register:
  - `GET /npm/{package}`
  - `GET /npm/@{scope}/{package}`
  - `GET /npm/{package}/-/{tarball}`
  - `GET /npm/@{scope}/{package}/-/{tarball}`
- Fetch package metadata from configured `upstreams.npm.registry_url`.
- Preserve scoped package names.

Likely files:

- `src/server.rs`
- `src/npm.rs`

Verification:

```sh
cargo test npm
```

## Milestone 2: npm Metadata Filtering and URL Rewriting

Problem: clients must not see blocked versions, and allowed artifacts must flow back through the proxy for a second policy check.

Desired behavior: npm metadata is filtered per version and allowed tarball URLs point to `osv-proxy`.

Acceptance criteria:

- Use `time` metadata where available for `published_at`.
- Build canonical `Artifact` for each version.
- Remove blocked versions from `versions`.
- Preserve `dist.integrity` and `dist.shasum`.
- Rewrite `dist.tarball` to `{server.public_base_url}/npm/{package}/-/{tarball}`.
- Recompute `dist-tags` by removing tags pointing to missing versions.

Likely files:

- `src/npm.rs`

Verification:

```sh
cargo test npm_metadata
```

## Milestone 3: npm Artifact Redirect Gate

Problem: lockfiles may already contain proxy artifact URLs, so artifact serving needs a second policy check.

Desired behavior: tarball routes infer package/version, evaluate policy, and redirect only if allowed.

Acceptance criteria:

- Infer version from npm tarball names such as `lodash-4.17.21.tgz` and scoped package tarballs such as `core-7.24.0.tgz`.
- Fetch metadata if needed to recover publish time and upstream tarball URL.
- Return 403 structured decision JSON when blocked.
- Return 302/303 redirect to upstream tarball URL when allowed.

Likely files:

- `src/npm.rs`

Verification:

```sh
cargo test npm_artifact
```

## Milestone 4: npm Adapter Tests

Problem: behavior must be proven without live npm or OSV calls.

Desired behavior: tests exercise filtering and redirect using in-process or local mocked upstreams and fake policy outcomes.

Acceptance criteria:

- A blocked version is removed from metadata.
- A too-new version is removed from metadata.
- An allowed version remains.
- Tarball URL points to `osv-proxy`.
- Dist-tags do not point to blocked versions.
- Allowed tarball returns redirect.
- Blocked tarball returns 403.

Verification:

```sh
cargo test npm
cargo test
```

## Final Response Requirements

Report:

- Files changed.
- Commands run.
- Test results.
- Any commits made.
- Residual risks or intentionally deferred product scope.
