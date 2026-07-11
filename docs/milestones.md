# Milestones

## OSV Vulnerability Severity Policy

The current implementation blocks active OSV vulnerabilities by default across
npm, PyPI, Cargo, Go, NuGet, and RubyGems. It supports inclusive CVSS thresholds,
unscored and malformed-severity behavior, bounded live detail hydration, and a
generation-scoped all-advisory SQLite store. `osv sync` is canonical;
`malicious sync` is retained as an alias. See [policy](policy.md) and
[OSV advisory data](osv-data.md).

Maven is supported by the same policy and local advisory store.

Cargo/crates.io sparse replacement filters index records, rechecks policy at
artifact delivery, and supports redirect or proxy artifact behavior.

RubyGems support filters the Bundler Compact Index, rechecks direct `.gem`
downloads, and supports redirect or proxy artifact behavior. Legacy Marshal
indexes and publishing are outside the supported surface.

Maven Central support filters release metadata for Maven and Gradle and
rechecks POMs, JARs, Gradle module metadata, classifiers, signatures, and
checksums. Snapshots, authentication, publishing, search, and repository
aggregation are outside the supported surface.

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

Then add PyPI, local malicious mode, metadata cache, and S3 artifact cache
mode. MongoDB-compatible malicious storage remains a possible future backend if
SQLite is not enough.

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
- OSV API failure follows `policy.osv.on_error`
- `allowlist.bypass_osv=true` allows exact package version

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

- PyPI Simple JSON-backed route with HTML/JSON responses
- upstream fetch
- file record parsing
- version extraction from filename
- hash preservation
- `upload-time` extraction for the age gate
- policy filtering
- file URL rewriting
- PyPI file redirect gate

Acceptance tests:

- blocked PyPI file removed from Simple response
- too-new PyPI file removed from Simple response
- missing `upload-time` follows policy
- allowed PyPI file remains
- file link points to `osv-proxy`
- JSON `versions` contains only versions with allowed files
- file route checks policy again
- allowed file returns redirect
- blocked file returns 403

## Milestone 5: Local Malicious Mode with SQLite Store

Build:

- local SQLite malicious checker behind the existing `MaliciousChecker`
  boundary
- SQLite sync engine storing advisory metadata, optional raw advisory JSON,
  normalized affected packages, exact versions, ranges, range events, and sync
  state
- explicit `osv-proxy malicious sync --config <path>` command
- background OSV `MAL-*` sync in `serve`
- local lookup

Acceptance tests:

- sync stores `MAL` records
- lookup finds malicious package by ecosystem/name/version
- local mode does not call OSV API during request handling
- exact affected versions and OSV range events are evaluated locally
- stale, missing, corrupt, or unhealthy local data fails closed by default

Status: implemented with SQLite. MongoDB-compatible and mongolino storage remain
future options if still desired.

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

## Milestone 7: Plain Artifact Proxy Mode

Build:

- proxy artifact streaming
- `artifacts.behavior: proxy`
- unsupported `proxy_cache_s3` validation

Acceptance tests:

- proxy mode streams upstream bytes
- redirect mode remains the default
- policy is checked before proxying artifacts
- blocked artifacts return 403 without fetching upstream artifact bytes

Status: implemented.

## Milestone 8: S3 Artifact Cache Mode

Build:

- `proxy_cache_s3`
- S3-compatible storage
- cache hit/miss logic
- hash-aware object keys where possible

Acceptance tests:

- `proxy_cache_s3` serves cache hits
- `proxy_cache_s3` writes cache misses
- policy is checked before serving S3 cached artifact
- blocked cached artifact returns 403

Status: future.

## Milestone 9: Hardening and Client Compatibility

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
