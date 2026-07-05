# osv-proxy

`osv-proxy` is a package-registry policy proxy for npm and PyPI.

It sits between package managers and public registries, filters package metadata
through deterministic policy, and checks the same policy again before redirecting
artifact downloads upstream. The first implementation is intentionally small:
naive OSV lookup, redirect-only artifacts, no local storage, and no metadata
cache.

## What It Does

- Blocks package versions that are too new for the configured minimum age.
- Blocks package versions with OSV malicious-package records whose IDs start
  with `MAL-`.
- Supports exact-version allowlist exceptions.
- Supports exact-version and whole-package blocklist entries.
- Filters npm metadata and PyPI Simple project metadata so blocked versions are
  not offered to clients.
- Rewrites allowed artifact URLs back through `osv-proxy`, then redirects to the
  upstream registry only after a second policy check.

## Current Scope

Implemented now:

- npm metadata filtering and tarball redirects.
- PyPI Simple JSON-backed filtering, HTML/JSON responses, and file redirects.
- YAML config loading and validation.
- `serve`, `check`, and `config validate` commands.
- Naive OSV API checks during request handling.
- Redirect artifact behavior.

Not implemented yet:

- Local malicious-package storage.
- MongoDB or mongolino-backed sync.
- Metadata caching.
- Artifact proxying or S3 artifact caching.
- `sync-malicious`.
- Authentication, publishing, license policy, vulnerability severity policy, or
  broad package scanning.

## Install

Build from source:

```sh
cargo build --release
```

Run the binary with Cargo during development:

```sh
cargo run -- config validate --config examples/phase1/osv-proxy.yaml
```

## Quick Start

Validate the example config:

```sh
cargo run -- config validate --config examples/phase1/osv-proxy.yaml
```

Start the proxy:

```sh
cargo run -- serve --config examples/phase1/osv-proxy.yaml
```

Point npm at the proxy:

```sh
npm config set registry http://127.0.0.1:8080/npm/
```

Point pip at the proxy:

```sh
pip config set global.index-url http://127.0.0.1:8080/pypi/simple/
```

Use `uv` with the proxy:

```sh
uv pip install --index-url http://127.0.0.1:8080/pypi/simple/ requests
```

## Check a Package

`check` evaluates one canonical package version and prints the policy decision:

```sh
cargo run -- check npm:lodash@4.17.21 \
  --config examples/phase1/osv-proxy.yaml \
  --published-at 2026-06-01T00:00:00Z
```

Package identities use this form:

```text
npm:lodash@4.17.21
npm:@babel/core@7.24.0
pypi:requests@2.32.3
```

The current `check` command does not fetch registry publish time by itself. With
the default `missing_publish_time: block`, pass `--published-at` when checking a
package that should be evaluated against the age gate.

## Configuration

The supported phase-one config is:

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

Unsupported modes fail config validation. In this phase, `policy.malicious.mode`
must be `naive`, `metadata_cache.enabled` must be `false`, and
`artifacts.behavior` must be `redirect`.

## Policy Behavior

For every package version or file, `osv-proxy` evaluates:

1. Exact-version allowlist.
2. OSV malicious records, using only `MAL-*` IDs by default.
3. Manual blocklist.
4. Minimum package age.
5. Missing publish time behavior.

Blocked artifact requests return HTTP `403` with a structured JSON decision.
Allowed artifact requests return HTTP `302` to the upstream tarball or file URL.

For PyPI project pages, `osv-proxy` fetches upstream Simple JSON and uses
`files[].upload-time` for the age gate. If a client requests
`application/vnd.pypi.simple.v1+json`, the proxy returns filtered Simple JSON.
Otherwise it renders filtered Simple HTML from the same JSON-backed policy
model.

## Development

Run the test suite:

```sh
cargo test
```

Run the route-level end-to-end tests:

```sh
cargo test e2e
```

Format check:

```sh
cargo fmt --check
```

## More Documentation

- [Policy model](docs/policy.md)
- [Configuration reference](docs/configuration.md)
- [Registry behavior](docs/registry-behavior.md)
- [Client configuration](docs/client-configuration.md)
- [Architecture notes](docs/architecture.md)
- [Milestones](docs/milestones.md)
