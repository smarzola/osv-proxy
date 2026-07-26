# Review registry and HTTP behavior

This reference describes the supported read-only routes and their policy,
cache, and package-file behavior.

## Common policy behavior

Metadata routes remove denied versions or files before a package manager
resolves a dependency. Retained download URLs point back through
`osv-proxy`.

Package-file routes rebuild the exact canonical artifact and evaluate current
policy before redirecting or contacting the upstream file origin. They never
use the metadata cache.

The default OSV policy has the following effects:

- A matching `MAL-*` record blocks with reason `malicious`.
- Another active matching advisory blocks with reason `vulnerable` when it
  meets the inclusive CVSS threshold.
- At the default threshold of zero, matching unscored advisories also block.
- An exact allowlist entry with `bypass_osv: true` is the only OSV bypass.

## HTTP status behavior

| Condition | Response |
| --- | --- |
| Direct policy denial | HTTP `403` with a structured decision |
| Route not found or requested file does not match registry metadata | HTTP `404` |
| Unsupported method on an owned route | HTTP `405` |
| Ingress or outbound-capacity timeout | HTTP `503` with `Retry-After: 1` |
| Invalid or failed upstream response | Structured gateway error |
| Allowed file in redirect mode | HTTP `302` |
| Allowed file in proxy mode | Validated upstream status, headers, and body |

A malicious-package denial has this form:

```json
{
  "allowed": false,
  "reason": "malicious",
  "package": "npm:some-package@1.2.3",
  "message": "Blocked by OSV malicious package record MAL-2026-000001",
  "source": "osv",
  "rule_id": "MAL-2026-000001"
}
```

A scored vulnerability denial has this form:

```json
{
  "allowed": false,
  "reason": "vulnerable",
  "package": "npm:some-package@1.2.3",
  "message": "Blocked by OSV vulnerability GHSA-abcd-1234 with CVSS base score 9.8",
  "source": "osv",
  "rule_id": "GHSA-abcd-1234",
  "cvss_score": 9.8
}
```

An age denial has this form:

```json
{
  "allowed": false,
  "reason": "too_young",
  "package": "pypi:example@0.1.0",
  "message": "Package version is younger than the configured minimum age of 72h",
  "published_at": "2026-07-05T10:00:00Z",
  "eligible_at": "2026-07-08T10:00:00Z"
}
```

## Health and readiness

`GET /healthz` returns dependency-free liveness:

```json
{"live":true}
```

Liveness remains outside ingress admission.

`GET /readyz` reports all seven local OSV datasets. A ready response returns
HTTP `200`. Missing, incomplete, unhealthy, or stale required data returns
HTTP `503`.

```json
{
  "ready": false,
  "osv_source": "local",
  "ecosystems": [
    {
      "ecosystem": "npm",
      "ready": true
    },
    {
      "ecosystem": "Maven",
      "ready": false,
      "message": "local malicious data for ecosystem Maven is stale"
    }
  ]
}
```

The example shortens the ecosystem list. The actual response includes every
supported ecosystem. Readiness uses the ingress budget; saturation returns
HTTP `503` without entering SQLite evaluation.

## Filtered metadata cache

The following responses can enter the cache after successful policy filtering:

| Ecosystem | Cached response |
| --- | --- |
| Cargo | Sparse index record |
| Go | Version list, latest version, and version information |
| Maven | Version-bearing metadata and owned checksum forms |
| npm | Package metadata |
| NuGet | Registration and flat-container version index |
| PyPI | Project Simple JSON or rendered HTML |
| RubyGems | Per-gem Compact Index info |

The cache key includes the exact path and query, representation and conditional
headers, range inputs, and the ecosystem's committed OSV content revision.
Identical misses share one fill, and distinct fills are bounded.

The cache does not retain non-success responses, overloads, oversized bodies,
or transient checker and revision errors. A content-changing OSV commit
advances the revision and makes older entries unreachable to new requests.

Static discovery responses and package-file routes remain outside the cache.

## Cargo sparse registry

Supported routes include:

- `GET /cargo/config.json`
- Cargo sparse index paths under `/cargo/`
- Proxy-owned `.crate` download paths

`/cargo/config.json` advertises proxy-owned downloads. The proxy validates and
filters sparse JSON-lines records without rewriting the bytes of retained
records. A filtered index response has a proxy-owned ETag and supports
`If-None-Match`.

A `.crate` request rebuilds package identity and evaluates current policy
before redirecting or streaming the exact upstream bytes.

## Go module proxy

The `/go/` prefix implements:

- `@v/list`
- `@latest`
- `@v/<version>.info`
- `@v/<version>.mod`
- `@v/<version>.zip`

The proxy applies Go's `!` escaping for uppercase module path and version
characters.

Version discovery enriches at most 256 versions with at most 16 requests in
flight, applies policy, and returns deterministic Go-semver order. An
enrichment error fails the discovery response closed.

Version information can enter the filtered metadata cache. `.mod` and `.zip`
requests remain uncached and evaluate current policy. Allowed module bytes
remain unchanged so Go checksum verification continues to work.

An upstream `404` or `410` remains a fallback signal for `GOPROXY`. Policy
denials use terminal HTTP `403`.

## Maven repository

The `/maven/` prefix exposes a read-only Maven Central-compatible release
repository for Maven and Gradle.

Version-bearing `maven-metadata.xml` removes denied versions before dynamic
selection. The proxy owns filtered ETags and matching checksum sidecars.
Conditional requests use weak ETag comparison. Bounded plugin-prefix metadata
passes through unchanged because it does not identify a package version.

Direct requests cover the following release files:

- POMs and JARs.
- Gradle `.module` metadata.
- Classifiers.
- Signatures.
- Checksums.

Each direct request resolves `groupId:artifactId:version` and evaluates current
policy. POM metadata supplies publication time and SHA-256 when available.
Other files do not inherit the POM hash.

`GET` and `HEAD` denials return structured HTTP `403`. Redirect mode validates
the upstream file with `HEAD` before it returns the location.

Snapshots, authentication, publishing, search, and multi-repository
aggregation are not supported. Client-side Maven and Gradle caches remain
outside proxy control.

## npm registry

Supported routes include:

- `GET /npm/{package}`
- `GET /npm/@{scope}/{package}`
- `GET /npm/{package}/-/{tarball}`
- `GET /npm/@{scope}/{package}/-/{tarball}`

For package metadata, the proxy performs the following steps:

1. Fetches upstream package metadata.
2. Builds one canonical artifact for each version.
3. Evaluates policy in a batch.
4. Removes denied versions.
5. Rewrites retained `dist.tarball` URLs through `osv-proxy`.
6. Preserves `dist.integrity` and `dist.shasum`.
7. Recomputes `dist-tags` so that they do not name removed versions.

A tarball request fetches the requested version's metadata and requires the
requested basename to match the upstream `dist.tarball` basename exactly. A
mismatch returns HTTP `404` without redirecting or fetching package bytes.

## NuGet V3 restore

Supported routes include:

- `GET /nuget/v3/index.json`
- `GET /nuget/v3/registration-semver2/{id}/...json`
- `GET /nuget/v3/flatcontainer/{id}/index.json`
- `GET /nuget/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg`
- `GET /nuget/v3/flatcontainer/{id}/{version}/{id}.nuspec`

The service index advertises only proxy-owned restore resources. Registration
and flat-container version indexes omit denied versions. Package and nuspec
requests evaluate policy again before delivery.

The proxy validates registration URLs discovered through the service index and
registration pages before it fetches their bounded JSON.

Search, publishing, deletion, symbols, authentication, and private registry
hosting are not supported.

## PyPI Simple API

Supported routes include:

- `GET /pypi/simple/`
- `GET /pypi/simple/{project}/`
- `GET /pypi/packages/{project}/{version}/{filename}`

The Simple root returns proxy-owned project links. The root does not enter the
filtered metadata cache.

For a project page, the proxy performs the following steps:

1. Normalizes the project name.
2. Fetches upstream Simple JSON.
3. Extracts filenames, versions, URLs, hashes, and `upload-time`.
4. Builds one canonical artifact for every file.
5. Evaluates policy in a batch.
6. Removes denied files.
7. Recomputes the `versions` collection from retained files.
8. Rewrites retained file URLs through `osv-proxy`.

When the client requests `application/vnd.pypi.simple.v1+json`, the proxy
returns filtered Simple JSON. Otherwise, it renders filtered Simple HTML from
the same model.

A package-file route fetches upstream Simple JSON, rebuilds the requested
artifact, and evaluates current policy before delivery.

## RubyGems Compact Index

Supported routes include:

- `GET /rubygems/versions`
- `GET /rubygems/info/{gem}`
- `GET /rubygems/gems/{filename}.gem`

The global versions index preserves upstream Compact Index behavior. It does
not enter the filtered metadata cache.

Per-gem info correlates each version and platform with bounded upstream
metadata, validates the checksum and publication time, applies policy in a
batch, and removes denied variants without rewriting retained lines. A
filtered body owns its ETag, SHA-256 `Digest` and `Repr-Digest`, conditional
behavior, and byte-range responses.

A gem request resolves the filename to exactly one validated package, version,
and platform tuple. Ambiguous or inconsistent metadata fails closed. The proxy
validates the checksum advertised by registry metadata; it does not
independently hash streamed content-delivery bytes.

Legacy Marshal indexes, standalone `gem install`, dependency and search APIs,
publishing, yanking, authentication, and private gem hosting are not
supported.

## Package-file delivery modes

Redirect mode is the default:

```text
client --> proxy-owned file URL
       --> current policy check
       --> 403 when denied
       --> 302 to the validated upstream URL when allowed
```

Proxy mode streams bytes:

```text
client --> proxy-owned file URL
       --> current policy check
       --> 403 when denied
       --> validated upstream fetch when allowed
       --> streamed status, headers, and body
```

Proxy mode forwards selected range and conditional request headers. It
preserves useful upstream response headers, including content type, length,
ETag, modification time, range information, cache control, and expiry.

Before it connects, the proxy validates the destination URL and resolved
addresses. Public HTTPS content-delivery origins are allowed. Plain HTTP and
non-public destinations require an exact configured ecosystem origin or an
explicit `artifacts.trusted_origins` entry. The request ignores system proxy
settings and rejects upstream redirects.

`proxy_cache_s3` is not implemented and fails configuration validation.

## Graceful shutdown

SIGINT and SIGTERM stop new connections and allow active registry requests and
streams 30 seconds to drain. After that interval, the server cancels remaining
route work and streams. Forced-close coordination can take up to one
additional second.
