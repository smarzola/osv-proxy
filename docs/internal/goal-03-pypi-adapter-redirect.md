# Goal: PyPI Simple Metadata Filtering and Redirect Artifacts

Working repo: `/Users/smarzola/projects/osv-proxy`

## Objective

Implement PyPI support for phase one: fetch upstream Simple HTML pages, evaluate files through the shared policy engine, remove blocked files, rewrite allowed file links to `osv-proxy` URLs, and recheck policy on PyPI file redirect routes.

This phase supports naive OSV mode and redirect artifacts only. Do not add metadata cache, local malicious storage, proxy streaming, or S3 cache behavior.

## Repository Rules

- Keep PyPI-specific parsing and URL logic in the PyPI adapter or route module.
- Normalize PyPI package names according to Python package-name rules.
- Keep the core policy model ecosystem-neutral.
- Do not add an in-process metadata cache.
- Preserve the invariant that policy is checked during metadata generation and checked again during artifact serving.
- Do not revert changes made by other workers. You are not alone in this codebase.

## Target State

- `GET /pypi/simple/` returns the upstream root Simple page or a compatible response.
- `GET /pypi/simple/{project}/` returns filtered Simple HTML.
- Allowed links preserve hash fragments and point to `osv-proxy` file routes.
- Blocked files are absent from Simple project pages.
- PyPI file routes re-evaluate policy and return either structured 403 JSON or a 302 redirect to upstream.

## Current State

This worker may receive the repo after the core scaffold exists. If core files are missing, stop and report that Goal 01 is required first.

## Definition of Done

1. PyPI Simple routes are implemented and covered by tests.
2. PyPI file redirect routes are implemented and covered by tests.
3. Tests use local mocked upstream responses, not the real PyPI service.
4. Policy is checked both when filtering Simple metadata and when serving file redirects.
5. `cargo test pypi` passes, and full `cargo test` passes.

## Milestone Checklist

- [x] PyPI route registration and upstream fetch
- [x] Simple HTML filtering and URL rewriting
- [x] PyPI file redirect gate
- [x] PyPI adapter tests

Status note, 2026-07-05: Implemented phase-one PyPI Simple route dispatch, Simple HTML filtering/link rewriting, and artifact redirect policy gates with mocked upstream tests. Verification commands run: `cargo fmt`; `cargo test pypi`; `cargo test pypi_simple`; `cargo test pypi_artifact`; `cargo test`. Commit: 1c6992c.

## Checkpoint Protocol

When a milestone is complete:

1. Run the milestone's verification commands.
2. Update this file by changing the milestone checkbox from `[ ]` to `[x]`.
3. Add a short status note with the date, exact commands run, and commit hash if available.
4. Commit the code, tests, docs, and status-note update with a focused commit message if committing is available in your workspace.
5. Report the commit hash or state that commits are unavailable before starting the next milestone.

## Milestone 1: PyPI Route Registration and Upstream Fetch

Problem: Python clients need Simple API compatible routes.

Desired behavior: the server accepts documented PyPI Simple and file routes.

Acceptance criteria:

- Register:
  - `GET /pypi/simple/`
  - `GET /pypi/simple/{project}/`
  - `GET /pypi/packages/{project}/{version}/{filename}`
- Fetch project pages from configured `upstreams.pypi.simple_url`.
- Normalize project names.

Likely files:

- `src/server.rs`
- `src/pypi.rs`

Verification:

```sh
cargo test pypi
```

## Milestone 2: Simple HTML Filtering and URL Rewriting

Problem: clients must not see blocked files, and allowed file downloads must flow back through the proxy.

Desired behavior: Simple HTML is filtered per file and allowed links point to `osv-proxy`.

Acceptance criteria:

- Parse anchor `href` links from Simple HTML.
- Preserve hash fragments such as `#sha256=...`.
- Extract version from common wheel and sdist filenames.
- Use available upload time metadata when present; otherwise follow missing publish-time policy.
- Build canonical `Artifact` for every file.
- Remove blocked file links.
- Rewrite allowed links to `{server.public_base_url}/pypi/packages/{project}/{version}/{filename}` plus original hash fragment.

Likely files:

- `src/pypi.rs`

Verification:

```sh
cargo test pypi_simple
```

## Milestone 3: PyPI File Redirect Gate

Problem: lockfiles may already contain proxy file URLs, so file serving needs a second policy check.

Desired behavior: file routes evaluate policy and redirect only if allowed.

Acceptance criteria:

- Build canonical `Artifact` from `{project}`, `{version}`, and `{filename}`.
- Recover upstream file URL from Simple metadata if needed.
- Return 403 structured decision JSON when blocked.
- Return 302/303 redirect to upstream file URL when allowed.

Likely files:

- `src/pypi.rs`

Verification:

```sh
cargo test pypi_artifact
```

## Milestone 4: PyPI Adapter Tests

Problem: behavior must be proven without live PyPI or OSV calls.

Desired behavior: tests exercise filtering and redirect using in-process or local mocked upstreams and fake policy outcomes.

Acceptance criteria:

- A blocked PyPI file is removed from Simple HTML.
- A too-new PyPI file is removed from Simple HTML.
- An allowed PyPI file remains.
- File link points to `osv-proxy`.
- Allowed file route returns redirect.
- Blocked file route returns 403.

Verification:

```sh
cargo test pypi
cargo test
```

## Final Response Requirements

Report:

- Files changed.
- Commands run.
- Test results.
- Any commits made.
- Residual risks or intentionally deferred product scope.
