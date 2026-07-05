# Registry Behavior

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

- `GET /healthz`: process is alive
- `GET /readyz`: dependencies required by current config are reachable

`/readyz` should check:

- config loaded
- malicious store reachable when local mode is enabled
- cachebox reachable when metadata cache is enabled
- S3 reachable when `proxy_cache_s3` mode is enabled

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
2. Optionally read/write raw metadata through cachebox.
3. Parse all versions.
4. Build an artifact for each version.
5. Evaluate policy.
6. Remove blocked versions from metadata.
7. Rewrite allowed versions' `dist.tarball` URLs to `osv-proxy` artifact URLs.
8. Preserve `dist.integrity` and `dist.shasum`.
9. Recompute `dist-tags` so they do not point to filtered versions.
10. Return filtered metadata.

Tarball requests must evaluate policy again before redirecting, proxying, or serving cached bytes.

## PyPI Routes

Supported routes:

- `GET /pypi/simple/`
- `GET /pypi/simple/{project}/`
- `GET /pypi/packages/{project}/{version}/{filename}`

Examples:

- `GET /pypi/simple/requests/`
- `GET /pypi/packages/requests/2.32.3/requests-2.32.3-py3-none-any.whl`

For `/pypi/simple/{project}/`:

1. Normalize project name.
2. Fetch upstream Simple API metadata.
3. Optionally read/write raw metadata through cachebox.
4. Parse file links.
5. Extract filename, version, upstream URL, hash, and upload time when available.
6. Build an artifact for every file/version.
7. Evaluate policy.
8. Remove blocked files.
9. Rewrite allowed file links to `osv-proxy` artifact URLs.
10. Return filtered Simple API response.

Support HTML Simple API first. Add JSON Simple API support as soon as practical.

File routes must evaluate policy again before redirecting, proxying, or serving cached bytes.

## Artifact Modes

Redirect mode is the default public-service mode:

```text
client -> osv-proxy artifact URL
osv-proxy -> policy check
if blocked -> 403
if allowed -> 302 redirect to upstream artifact URL
client -> downloads bytes from upstream registry/CDN
```

Proxy mode streams bytes through `osv-proxy` without persistent caching.

S3 cache mode checks S3 before fetching upstream, but policy must be checked before serving cached bytes.
