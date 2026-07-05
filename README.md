# osv-proxy

`osv-proxy` is a package-registry policy proxy for npm and PyPI.

It sits between package managers and public registries, filters package metadata
through deterministic policy, and checks the same policy again before redirecting
artifact downloads upstream.

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
cargo run -- config validate --config examples/basic/osv-proxy.yaml
```

## Quick Start

Validate the example config:

```sh
cargo run -- config validate --config examples/basic/osv-proxy.yaml
```

Start the proxy:

```sh
cargo run -- serve --config examples/basic/osv-proxy.yaml
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

`check` fetches upstream registry metadata, builds the same canonical artifact
context used by proxy routes, evaluates policy, and prints structured JSON:

```sh
cargo run -- check npm:lodash@4.17.21 \
  --config examples/basic/osv-proxy.yaml
```

PyPI checks evaluate every file published for the requested version and allow
the package only when every file is allowed:

```sh
cargo run -- check pypi:requests@2.32.3 \
  --config examples/basic/osv-proxy.yaml
```

Package identities use this form:

```text
npm:lodash@4.17.21
npm:@babel/core@7.24.0
pypi:requests@2.32.3
```

If upstream metadata is missing or malformed, `check` exits non-zero rather than
evaluating a synthetic artifact.

For manual policy evaluation without registry metadata, use `eval`. It is not
proxy-equivalent and only evaluates the artifact fields supplied on the command
line:

```sh
cargo run -- eval npm:lodash@4.17.21 \
  --config examples/basic/osv-proxy.yaml \
  --published-at 2026-06-01T00:00:00Z
```

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

The npm registry, PyPI Simple API, and OSV API default to their public URLs.
Set `upstreams` or `policy.malicious.osv_api_url` only when using a mirror,
fixture, or private gateway.

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
model. The PyPI Simple root is rendered with project links that stay on
`/pypi/simple/...` proxy routes.

## Development

Run the test suite:

```sh
cargo test
```

Run only the route-level policy flow tests:

```sh
cargo test e2e
```

Run only the package-manager end-to-end tests. These start local fixture
registries and a local proxy, then run `npm install` and `uv pip install`
against the proxy:

```sh
cargo test --test package_manager_e2e
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
