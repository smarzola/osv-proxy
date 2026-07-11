# osv-proxy

`osv-proxy` is a package-registry security proxy for npm, PyPI,
Cargo/crates.io, Go modules, NuGet restore, RubyGems/Bundler, and Maven Central
for Maven and Gradle. It combines the
[OSV vulnerability database](https://osv.dev/) with local policy.

It sits between package managers and public registries, filters package metadata
through deterministic policy backed by OSV data and local rules, and checks the
same policy again before delivering artifact downloads according to the
configured artifact behavior.

## What It Does

- Blocks package versions that are too new for the configured minimum age.
- Blocks package versions with active OSV malicious-package and vulnerability
  records.
- Supports exact-version allowlist exceptions.
- Supports exact-version and whole-package blocklist entries.
- Filters npm metadata and PyPI Simple project metadata so blocked versions are
  not offered to clients.
- Rewrites allowed artifact URLs back through `osv-proxy`, then either redirects
  to upstream or streams bytes through the proxy after a second policy check.

## Current Scope

Implemented now:

- npm metadata filtering and tarball delivery.
- PyPI Simple JSON-backed filtering, HTML/JSON responses, and file delivery.
- Go module proxy filtering for `@v/list`, `@latest`, `.info`, `.mod`, and `.zip`.
- NuGet V3 restore service discovery, registration filtering, flat-container
  version enumeration, and protected `.nupkg`/`.nuspec` delivery.
- RubyGems Compact Index filtering and protected `.gem` delivery for modern
  Bundler installs.
- Maven metadata filtering and protected POM, JAR, Gradle module metadata,
  classifier, signature, and checksum delivery for Maven and Gradle builds.
- YAML config loading and validation.
- `serve`, `check`, `eval`, `config validate`, `osv sync`, and the compatibility
  `malicious sync` commands.
- Live OSV API checks during request handling.
- Local SQLite OSV advisory checks with explicit and background OSV dump
  sync.
- Redirect artifact behavior and plain artifact proxy behavior.

Not implemented yet:

- Metadata caching.
- S3 artifact caching.
- Authentication, publishing, license policy, or
  broad package scanning.

## Install

Download a prebuilt binary from the
[GitHub releases](https://github.com/smarzola/osv-proxy/releases) page.

Release archives are named by version and target:

```text
osv-proxy-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
osv-proxy-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz
osv-proxy-vX.Y.Z-x86_64-apple-darwin.tar.gz
osv-proxy-vX.Y.Z-aarch64-apple-darwin.tar.gz
```

Each release also includes `SHA256SUMS`.

Build from source:

```sh
cargo build --release
```

Run the binary:

```sh
osv-proxy config validate --config examples/basic/osv-proxy.yaml
```

## License

`osv-proxy` is licensed under the Apache License, Version 2.0. OSV advisory
data and upstream vulnerability records retain their original source licenses
and attribution requirements when cached, exported, or redistributed.

## Quick Start

Validate the example config:

```sh
osv-proxy config validate --config examples/basic/osv-proxy.yaml
```

Start the proxy:

```sh
osv-proxy serve --config examples/basic/osv-proxy.yaml
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

Use Go modules with the proxy:

```sh
GOPROXY=http://127.0.0.1:8080/go GONOSUMDB='*' go mod download
```

For a mandatory policy gate, use a single proxy URL. `GOPROXY` values such as
`http://127.0.0.1:8080/go,direct` or a second public proxy allow Go to fall
back after upstream `404`/`410` responses and can bypass this proxy. Keep
private-module patterns out of `GONOPROXY`/`GOPRIVATE` when the proxy must
enforce policy. `osv-proxy` returns `403` for policy denials, which Go treats
as terminal rather than a fallback signal.

Use the proxy as the sole Bundler source in `Gemfile`:

```ruby
source "http://127.0.0.1:8080/rubygems/"
```

RubyGems support targets modern Bundler Compact Index installs. Standalone
legacy `gem install` index protocols, search, publishing, yanking, private
registry authentication, and gem hosting are unsupported.

Use Maven with a mirror whose `mirrorOf` is `*`:

```xml
<mirror>
  <id>osv-proxy</id>
  <url>http://127.0.0.1:8080/maven/</url>
  <mirrorOf>*</mirrorOf>
</mirror>
```

For Gradle, declare `http://127.0.0.1:8080/maven/` as the sole Maven repository
and enforce that repository policy in `settings.gradle`. Additional public
repositories can bypass the proxy. Already-cached artifacts cannot be revoked;
use a clean or refreshed dependency cache when validating a policy change.

## Check a Package

`check` fetches upstream registry metadata, builds the same canonical artifact
context used by proxy routes, evaluates policy, and prints structured JSON:

```sh
osv-proxy check npm:lodash@4.17.21 \
  --config examples/basic/osv-proxy.yaml
```

PyPI checks evaluate every file published for the requested version and allow
the package only when every file is allowed:

```sh
osv-proxy check pypi:requests@2.32.3 \
  --config examples/basic/osv-proxy.yaml
```

Package identities use this form:

```text
npm:lodash@4.17.21
npm:@babel/core@7.24.0
pypi:requests@2.32.3
go:github.com/pkg/errors@v0.9.1
rubygems:rails@8.0.2
maven:org.apache.commons:commons-lang3@3.17.0
```

If upstream metadata is missing or malformed, `check` exits non-zero rather than
evaluating a synthetic artifact.

For manual policy evaluation without registry metadata, use `eval`. It is not
proxy-equivalent and only evaluates the artifact fields supplied on the command
line:

```sh
osv-proxy eval npm:lodash@4.17.21 \
  --config examples/basic/osv-proxy.yaml \
  --published-at 2026-06-01T00:00:00Z
```

## Configuration

The default config is intentionally small:

```yaml
server:
  bind: "127.0.0.1:8080"
  public_base_url: "http://127.0.0.1:8080"
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    source: live
    on_error: "block"
artifacts:
  behavior: redirect
```

The npm registry, PyPI Simple API, Go module proxy, NuGet service index,
RubyGems registry, Maven Central repository, and OSV API default to their public URLs.
Set `upstreams` or `policy.osv.api_url` only when using a mirror, fixture, or
private gateway.

### OSV Data Source

`policy.osv.source: live` is the default. Live mode calls the OSV API during
metadata filtering, artifact serving, `check`, and `eval`.

`policy.osv.source: local` reads synchronized OSV advisory data from
SQLite instead. In local mode, install request handling performs indexed SQLite
reads plus in-memory exact-version and range evaluation; it does not call OSV.
Populate or refresh the local database with:

```sh
osv-proxy osv sync --config /path/to/osv-proxy.yaml
```

Local mode configuration:

```yaml
policy:
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    source: local
    on_error: block
    local:
      sqlite_path: "./osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      retain_raw_advisories: false
      background_sync: true
      sync_interval: "6h"
```

`on_error: block` and `on_stale: block` fail closed by default. Missing,
corrupt, incomplete, unhealthy, or stale local data blocks OSV checks instead of
silently allowing installs. `background_sync: true` makes `serve` run one sync
immediately on startup and then repeat after `sync_interval`; failed background
syncs record health state and keep serving against the last usable snapshot.
`retain_raw_advisories` defaults to false so the SQLite database stores compact
normalized lookup data by default; set it to true only when you need raw OSV
advisory JSON for audit or debugging.

## Policy Behavior

For every package version or file, `osv-proxy` evaluates:

1. Exact-version allowlist.
2. OSV `MAL-*` records when malicious blocking is enabled.
3. Other active OSV advisories whose score is at least `minimum_cvss_score`.
   The default threshold is zero, so matching unscored advisories also block.
4. Manual blocklist.
5. Minimum package age and missing publish time behavior.

This default is behavior-changing for operators upgrading from malicious-only
policy. Set `block_vulnerabilities: false` for the compatibility escape hatch;
`MAL-*` blocking remains controlled independently by `block_malicious`.

Blocked artifact requests return HTTP `403` with a structured JSON decision.
Allowed artifact requests return HTTP `302` to the upstream tarball or file URL
by default. With `artifacts.behavior: proxy`, allowed artifact requests stream
the upstream response body and useful artifact headers through `osv-proxy`.

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
registries and a local proxy, then run npm, uv/pip, Cargo, Go, .NET, and Bundler clients
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
- [OSV advisory data](docs/osv-data.md)
- [Architecture notes](docs/architecture.md)
- [Milestones](docs/milestones.md)
