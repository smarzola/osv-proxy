# Configuration

`osv-proxy` uses YAML configuration.

## Full Example

```yaml
server:
  listen: "0.0.0.0:8080"
  public_base_url: "https://packages.example.com"
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
    mode: "local"
    only_mal_ids: true
    osv_api_url: "https://api.osv.dev"
    on_osv_error: "block"
allowlist:
  - ecosystem: npm
    name: "@company/safe-package"
    version: "1.2.3"
    bypass_age_gate: true
    bypass_malicious: false
    reason: "Internal emergency release"
  - ecosystem: pypi
    name: "false-positive-example"
    version: "0.9.1"
    bypass_age_gate: true
    bypass_malicious: true
    reason: "False positive confirmed by security team"
blocklist:
  - ecosystem: npm
    name: "event-stream"
    versions: ["*"]
    reason: "Manually blocked"
metadata_cache:
  enabled: false
malicious_store:
  mongodb:
    uri: "mongodb://127.0.0.1:27018"
    database: "osv_proxy"
    collection: "malicious_packages"
  sync:
    enabled: true
    interval: "15m"
    ecosystems: ["npm", "PyPI"]
artifacts:
  behavior: "redirect"
  s3:
    endpoint: "http://localhost:9000"
    bucket: "osv-proxy-artifacts"
    region: "us-east-1"
    access_key_id_env: "AWS_ACCESS_KEY_ID"
    secret_access_key_env: "AWS_SECRET_ACCESS_KEY"
    force_path_style: true
observability:
  audit_log: true
  metrics: true
  log_level: "info"
```

## Minimal Developer Config

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
    on_osv_error: "allow"
metadata_cache:
  enabled: false
artifacts:
  behavior: "redirect"
```

## Recommended Public Deployment Config

```yaml
server:
  listen: "0.0.0.0:8080"
  public_base_url: "https://packages.example.com"
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  malicious:
    mode: "local"
    only_mal_ids: true
    on_osv_error: "block"
malicious_store:
  mongodb:
    uri: "mongodb://127.0.0.1:27018"
    database: "osv_proxy"
    collection: "malicious_packages"
  sync:
    enabled: true
    interval: "15m"
    ecosystems: ["npm", "PyPI"]
metadata_cache:
  enabled: true
  backend: "cachebox"
  ttl: "5m"
  stale_ttl: "1h"
  cachebox:
    address: "127.0.0.1:7777"
    namespace: "osv-proxy-metadata"
artifacts:
  behavior: "redirect"
```

The recommended public deployment can point `malicious_store.mongodb.uri` at mongolino for a cheap single-file local store, or at MongoDB for a managed or multi-instance deployment. `osv-proxy` should not expose a separate `mongolino` config branch.

## Metadata Cache

Allowed modes:

- disabled
- cachebox

Do not implement an in-process memory metadata cache.

Cache raw upstream metadata, not policy-filtered metadata. Always apply current policy after reading from cache.

## Artifact Behavior

Allowed modes:

- `redirect`
- `proxy`
- `proxy_cache_s3`

Always check policy before serving any artifact, including S3 cache hits.
