# Milestones

## First End-to-End Target

1. Rust binary
2. YAML config
3. naive OSV mode
4. no metadata cache
5. npm metadata filtering
6. npm artifact redirect
7. age gate
8. `MAL-*` block
9. exact allowlist

Then add PyPI, local mongolino mode, cachebox, and proxy/S3 artifact modes.

## Milestone 1: Config and Policy Engine

Build:

- YAML config parser
- artifact model
- decision model
- age gate
- exact-version allowlist
- manual blocklist
- unit tests
- `osv-proxy check` command

Acceptance tests:

- old package is allowed
- too-new package is blocked
- missing publish time follows config
- exact allowlist bypasses age gate
- manual blocklist blocks package
- malicious bypass flag is parsed but not yet wired

## Milestone 2: OSV Naive Mode

Build:

- OSV API client
- query single package/version
- filter `MAL-*` records
- wire malicious check into policy engine

Acceptance tests:

- `MAL-*` result blocks package
- non-`MAL` advisory does not block package
- OSV API failure follows `on_osv_error`
- `allowlist.bypass_malicious=true` allows exact package version

## Milestone 3: npm Metadata and Redirect

Build:

- npm metadata route
- upstream fetch
- version extraction
- `published_at` extraction
- policy filtering
- `dist.tarball` rewriting
- dist-tag recomputation
- npm tarball redirect gate

Acceptance tests:

- blocked npm version removed from metadata
- too-new npm version removed from metadata
- allowed npm version remains
- `dist.tarball` points to `osv-proxy`
- dist-tags do not point to blocked versions
- tarball route checks policy again
- allowed tarball returns redirect
- blocked tarball returns 403

## Milestone 4: PyPI Simple API and Redirect

Build:

- PyPI Simple HTML route
- upstream fetch
- file link parsing
- version extraction from filename
- hash preservation
- policy filtering
- file URL rewriting
- PyPI file redirect gate

Acceptance tests:

- blocked PyPI file removed from Simple page
- too-new PyPI file removed from Simple page
- allowed PyPI file remains
- file link points to `osv-proxy`
- file route checks policy again
- allowed file returns redirect
- blocked file returns 403

## Milestone 5: Local Malicious Mode with mongolino/MongoDB-Compatible Store

Build:

- `MaliciousPackageStore` trait
- MongoDB-compatible implementation
- mongolino config support
- background OSV `MAL` sync
- `sync-malicious` command
- local lookup

Acceptance tests:

- sync stores `MAL` records
- lookup finds malicious package by ecosystem/name/version
- local mode does not call OSV API during request handling
- mongolino-backed store works through MongoDB-compatible client
- MongoDB-backed store works with same interface

## Milestone 6: cachebox Metadata Cache

Build:

- `NoopMetadataCache`
- `CacheboxMetadataCache`
- cache config
- raw metadata caching

Acceptance tests:

- disabled cache always fetches upstream
- enabled cache uses cachebox
- policy applies after cache read
- updated malicious store blocks package even when metadata is cached
- no memory metadata cache implementation exists

## Milestone 7: Proxy and S3 Artifact Modes

Build:

- proxy artifact streaming
- `proxy_cache_s3`
- S3-compatible storage
- cache hit/miss logic
- hash-aware object keys where possible

Acceptance tests:

- proxy mode streams upstream bytes
- `proxy_cache_s3` serves cache hits
- `proxy_cache_s3` writes cache misses
- policy is checked before serving S3 cached artifact
- blocked cached artifact returns 403

## Milestone 8: Hardening and Client Compatibility

Test clients:

- npm
- pnpm
- yarn classic
- yarn berry
- bun
- pip
- uv
- poetry

Test scenarios:

- fresh install
- lockfile install
- blocked version after lockfile creation
- age-gated latest version
- allowlisted exact version
- malicious exact version
- metadata cache enabled
- metadata cache disabled
- redirect mode
- proxy mode
- `proxy_cache_s3` mode
