# Configuration

`osv-proxy` uses YAML configuration. Unknown keys fail validation so policy
typos do not silently change install behavior.

## Example

```yaml
server:
  listen: "127.0.0.1:8080"
  public_base_url: "http://127.0.0.1:8080"
upstreams:
  npm:
    registry_url: "https://registry.npmjs.org"
  pypi:
    simple_url: "https://pypi.org/simple"
    files_url: "https://files.pythonhosted.org"
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  malicious:
    mode: "naive"
    only_mal_ids: true
    osv_api_url: "https://api.osv.dev"
    on_osv_error: "block"
metadata_cache:
  enabled: false
artifacts:
  behavior: "redirect"
```

Validate it with:

```sh
cargo run -- config validate --config examples/basic/osv-proxy.yaml
```

The npm registry, PyPI Simple API, and OSV API default to their public URLs.
Configure them only when routing through a mirror, fixture, or private gateway.

## Server

```yaml
server:
  listen: "127.0.0.1:8080"
  public_base_url: "http://127.0.0.1:8080"
```

- `listen`: local socket address for the HTTP server.
- `public_base_url`: URL used when rewriting npm tarballs and PyPI file links
  back through `osv-proxy`.

## Upstreams

```yaml
upstreams:
  npm:
    registry_url: "https://registry.npmjs.org"
  pypi:
    simple_url: "https://pypi.org/simple"
    files_url: "https://files.pythonhosted.org"
```

- `npm.registry_url`: upstream npm registry metadata endpoint.
- `pypi.simple_url`: upstream PyPI Simple API endpoint. Project pages are
  fetched as Simple JSON for policy evaluation.
- `pypi.files_url`: reserved for file URL configuration. Current file redirects
  use URLs from upstream Simple JSON project metadata.

Both upstream values have the public registry defaults shown above, so most
local configs can omit this section.

## Policy

```yaml
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  malicious:
    mode: "naive"
    only_mal_ids: true
    osv_api_url: "https://api.osv.dev"
    on_osv_error: "block"
```

- `minimum_age`: minimum age before a package version can be installed. It must
  be a valid duration that fits policy evaluation.
- `missing_publish_time`: `block` or `allow`.
- `malicious.mode`: must be `naive` in this phase.
- `malicious.only_mal_ids`: when true, only OSV records with IDs starting with
  `MAL-` block package versions.
- `malicious.osv_api_url`: optional OSV API base URL override. Omit it to use
  `https://api.osv.dev`.
- `malicious.on_osv_error`: `block` fails closed; `allow` fails open when the
  OSV check fails or a required OSV result is missing.

CVEs, GHSAs, and other advisory records are not package-malicious decisions in
`osv-proxy` unless `malicious.only_mal_ids` is explicitly set to false.

## Allowlist

Allowlist entries are exact-version only.

```yaml
allowlist:
  - ecosystem: npm
    name: "@company/safe-package"
    version: "1.2.3"
    bypass_age_gate: true
    bypass_malicious: false
    reason: "Internal emergency release"
```

`bypass_malicious: true` requires a non-empty `reason`.

## Blocklist

Blocklist entries support exact versions and `*`.

```yaml
blocklist:
  - ecosystem: npm
    name: "event-stream"
    versions: ["*"]
    reason: "Manually blocked"
```

Version ranges such as `<4.17.21` are not supported.
