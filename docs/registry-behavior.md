# Registry Behavior

## Cargo sparse registry

`/cargo/config.json` provides proxy downloads. Sparse JSON-lines records are
validated and policy-filtered without rewriting retained bytes. Filtered index
responses have a content ETag and support `If-None-Match`; direct `.crate`
downloads recheck policy before redirecting or proxying exact upstream bytes.

Under the default OSV policy, metadata omits versions matching either `MAL-*`
or other active advisories at the inclusive CVSS threshold. Direct npm
tarballs, PyPI files, Cargo crates, Go `.mod`/`.zip` files, and NuGet
`.nupkg`/`.nuspec` requests rebuild the canonical artifact and re-run the same
policy before fetching package bytes. Denials use `reason: malicious` for
`MAL-*` and `reason: vulnerable` for other advisories. An exact allowlist with
`bypass_osv: true` is the only OSV bypass.

## HTTP Responses

Blocked requests return HTTP 403 with the structured decision model.

Malicious block:

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

Scored vulnerability block:

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

Unscored vulnerability block at the default zero threshold (`cvss_score` is
omitted when absent):

```json
{
  "allowed": false,
  "reason": "vulnerable",
  "package": "pypi:some-package@1.2.3",
  "message": "Blocked by OSV vulnerability GHSA-wxyz-5678",
  "source": "osv",
  "rule_id": "GHSA-wxyz-5678"
}
```

Age-gate block:

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

Manual block:

```json
{
  "allowed": false,
  "reason": "manually_blocked",
  "package": "npm:event-stream@3.3.6",
  "message": "Blocked by local blocklist: Known problematic package"
}
```

## Health Endpoints

Health endpoints are not implemented in the current phase.

Future `/healthz` and `/readyz` endpoints should report process health and
configured dependency readiness.

## npm Routes

Supported routes:

- `GET /npm/{package}`
- `GET /npm/@{scope}/{package}`
- `GET /npm/{package}/-/{tarball}`
- `GET /npm/@{scope}/{package}/-/{tarball}`

Examples:

- `GET /npm/lodash`
- `GET /npm/@babel/core`
- `GET /npm/lodash/-/lodash-4.17.21.tgz`
- `GET /npm/@babel/core/-/core-7.24.0.tgz`

For metadata requests:

1. Fetch raw metadata from upstream npm registry.
2. Parse all versions.
3. Build an artifact for each version.
4. Evaluate policy.
5. Remove blocked versions from metadata.
6. Rewrite allowed versions' `dist.tarball` URLs to `osv-proxy` artifact URLs.
7. Preserve `dist.integrity` and `dist.shasum`.
8. Recompute `dist-tags` so they do not point to filtered versions.
9. Return filtered metadata.

Tarball requests fetch the version's upstream metadata, require the requested
tarball basename to exactly match that version's upstream `dist.tarball`
basename, and then evaluate policy again before artifact delivery. A basename
mismatch returns `404` and does not fetch or redirect artifact bytes.

## PyPI Routes

Supported routes:

- `GET /pypi/simple/`
- `GET /pypi/simple/{project}/`
- `GET /pypi/packages/{project}/{version}/{filename}`

## NuGet V3 Restore Routes

Supported read-only restore routes:

- `GET /nuget/v3/index.json`
- `GET /nuget/v3/registration-semver2/{id}/...json`
- `GET /nuget/v3/flatcontainer/{id}/index.json`
- `GET /nuget/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg`
- `GET /nuget/v3/flatcontainer/{id}/{version}/{id}.nuspec`

The service index advertises only these proxy-owned resources. Registration and
flat-container discovery omit versions denied by policy; package bytes are
rechecked before redirect or proxy delivery. Search, publish, delete, symbols,
and authentication are unsupported.

Examples:

- `GET /pypi/simple/requests/`
- `GET /pypi/packages/requests/2.32.3/requests-2.32.3-py3-none-any.whl`

For `/pypi/simple/{project}/`, policy is evaluated from upstream Simple JSON
project metadata. This matters because the JSON API provides `files[].upload-time`
for the age gate.

For `/pypi/simple/`, the proxy fetches the upstream Simple root and renders a
minimal root page whose project links point at
`{server.public_base_url}/pypi/simple/{project}/`. Upstream `/simple/...`
links are not passed through to clients.

1. Normalize project name.
2. Fetch upstream Simple JSON metadata.
3. Extract filename, version, upstream URL, hashes, and `upload-time`.
4. Build an artifact for every file/version.
5. Evaluate policy.
6. Remove blocked files.
7. Recompute `versions` from allowed files.
8. Rewrite allowed file URLs to `osv-proxy` artifact URLs.
9. Return filtered Simple JSON when the client requests
   `application/vnd.pypi.simple.v1+json`.
10. Otherwise render a filtered Simple HTML page from the same filtered JSON
    model.

File routes fetch upstream Simple JSON, rebuild the requested artifact, and
evaluate policy again before artifact delivery.

## Go module routes

`/go/` implements the read-only GOPROXY routes `@v/list`, `@latest`,
`@v/<version>.info`, `.mod`, and `.zip`. The proxy escapes uppercase module
path and version characters using Go's `!` encoding. It enriches at most 256
listed versions with at most 16 in flight, filters each one by policy, and
returns a deterministic Go-semver-sorted result. An enrichment error fails the
discovery response closed. Direct `.info`, `.mod`, and `.zip` requests rebuild
the canonical artifact and re-evaluate policy; denials are terminal `403`.

Allowed `.mod` and `.zip` bytes are redirected or streamed unchanged, so Go's
module checksum verification remains valid. A missing upstream module remains
`404`/`410`, which is the only response class that permits GOPROXY fallback.

## Artifact Modes

Redirect mode is the default public-service mode:

```text
client -> osv-proxy artifact URL
osv-proxy -> policy check
if blocked -> 403
if allowed -> 302 redirect to upstream artifact URL
client -> downloads bytes from upstream registry/CDN
```

Plain proxy mode streams allowed artifact bytes through `osv-proxy`:

```text
client -> osv-proxy artifact URL
osv-proxy -> policy check
if blocked -> 403
if allowed -> fetch verified upstream artifact URL
osv-proxy -> stream upstream status, body, and useful artifact headers
```

Proxy mode forwards selected request headers such as `Range`, `If-None-Match`,
and `If-Modified-Since`. It preserves useful upstream artifact response headers
such as `Content-Type`, `Content-Length`, `ETag`, `Last-Modified`,
`Accept-Ranges`, `Content-Range`, `Cache-Control`, and `Expires`.

`proxy_cache_s3` is not implemented. Configurations that select it are rejected
until a future S3 cache milestone implements cache reads and writes.
