# Review support status and roadmap

This page summarizes implemented and planned product areas. It describes the
present product; release history belongs in the
[changelog](../CHANGELOG.md).

## Implemented capabilities

| Area | Status |
| --- | --- |
| Cargo sparse registry | Filters index records and protects `.crate` files |
| Go module proxy | Filters discovery and protects `.info`, `.mod`, and `.zip` |
| Maven Central | Filters release metadata for Maven and Gradle and protects release files |
| npm registry | Filters package metadata and protects tarballs |
| NuGet V3 restore | Filters registration and version indexes and protects restore files |
| PyPI Simple API | Filters JSON and HTML project pages and protects distribution files |
| RubyGems Compact Index | Filters Bundler metadata and protects `.gem` files |
| OSV policy | Blocks malicious packages and threshold-matching vulnerabilities from local SQLite |
| Local policy | Applies minimum age, exact allowlists, and manual blocklists |
| OSV synchronization | Supports explicit and automatic hourly synchronization |
| Filtered metadata cache | Provides bounded, revision-aware, process-local response caching |
| Package-file delivery | Supports redirect and streaming-proxy modes |
| Runtime hardening | Provides request budgets, outbound origin validation, readiness, and graceful shutdown |

## Client compatibility

The package-manager end-to-end suite covers the following clients:

- Bundler.
- Cargo.
- Go.
- Gradle.
- Maven.
- npm.
- NuGet through `dotnet restore`.
- pip and uv.

The suite exercises fresh resolution, locked state, post-lock denial, redirect
delivery, and streaming-proxy delivery where each protocol supports those
scenarios.

## Planned capabilities

The following areas remain possible future work. They have no accepted
configuration or compatibility contract:

- S3-compatible package-file caching.
- MongoDB-compatible OSV advisory storage.
- Authentication and publishing controls.
- License policy.
- A structured audit-log and metrics exporter.
- Additional package-manager protocols.

## Scope limits

The current product intentionally excludes the following behavior:

- Maven snapshots and multi-repository aggregation.
- Legacy RubyGems Marshal indexes and standalone `gem install`.
- NuGet search, publishing, deletion, and symbols.
- Package publishing for every ecosystem.
- Revocation of files already stored in a package manager's local cache.

For exact paths and HTTP behavior, see
[Review registry and HTTP behavior](registry-behavior.md). For release-by-release
changes, see the [changelog](../CHANGELOG.md).
