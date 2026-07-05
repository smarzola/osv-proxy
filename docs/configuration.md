# Configuration

`osv-proxy` uses YAML configuration.

This page describes the configuration that is supported by the current
phase-one implementation. Future storage, cache, and proxy modes are documented
in product planning docs, but they do not validate in the current binary.

## Minimal Supported Config

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
cargo run -- config validate --config examples/phase1/osv-proxy.yaml
```

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

- `minimum_age`: minimum age before a package version can be installed.
- `missing_publish_time`: `block` or `allow`.
- `malicious.mode`: must be `naive` in this phase.
- `malicious.only_mal_ids`: when true, only OSV IDs starting with `MAL-` block.
- `malicious.osv_api_url`: OSV API base URL.
- `malicious.on_osv_error`: `block` fails closed; `allow` fails open.

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

Version ranges such as `<4.17.21` are not supported in this phase.

## Metadata Cache

The only supported cache setting is disabled:

```yaml
metadata_cache:
  enabled: false
```

`metadata_cache.enabled: true` and cache backend settings fail validation.

## Artifact Behavior

The only supported artifact behavior is redirect:

```yaml
artifacts:
  behavior: "redirect"
```

`proxy` and `proxy_cache_s3` fail validation in this phase.

## Unsupported In This Phase

These settings intentionally fail validation:

- `policy.malicious.mode: local`
- `malicious_store`
- `metadata_cache.enabled: true`
- `metadata_cache.backend`
- `artifacts.behavior: proxy`
- `artifacts.behavior: proxy_cache_s3`
- `artifacts.s3`

The implementation has no local malicious store, no MongoDB or mongolino sync,
no cachebox backend, no in-process metadata cache, and no S3 artifact cache.
