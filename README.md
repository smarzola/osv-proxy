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
mkdir -p data
osv-proxy osv sync --config examples/basic/osv-proxy.yaml
osv-proxy serve --config examples/basic/osv-proxy.yaml
```

The example uses the local SQLite OSV source by default. Preseeding the
database before `serve` keeps startup independent of the OSV network and makes
the first request follow the same fast path as steady-state requests. See
[Performance and fast boot](docs/performance.md) for CI, image, and deployment
patterns.

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
    source: local
    on_error: "block"
    local:
      sqlite_path: "./data/osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      background_sync: false
artifacts:
  behavior: redirect
```

The npm registry, PyPI Simple API, Go module proxy, NuGet service index,
RubyGems registry, Maven Central repository, and OSV API default to their public URLs.
Set `upstreams` or `policy.osv.api_url` only when using a mirror, fixture, or
private gateway.

For a shared or non-loopback deployment, place `osv-proxy` behind a trusted
gateway or reverse proxy that provides TLS, authentication, client rate
limiting, and edge access control. The process enforces configurable global
ingress and outbound-request budgets, exposes `/healthz` and `/readyz`, and
gracefully drains SIGINT/SIGTERM; see [configuration](docs/configuration.md) for
the runtime limits and readiness contract.

### OSV Data Source

`policy.osv.source: local` is the default. Local mode reads synchronized SQLite
advisory data during metadata filtering, artifact serving, `check`, and `eval`;
it makes no OSV network request on the install path.

`policy.osv.source: live` is an explicit opt-in for deployments that prefer
fresh remote OSV queries over a preseeded local dataset. Live mode calls the OSV
API during policy evaluation and remains bounded by the process egress budget.
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
      sqlite_path: "./data/osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: block
      retain_raw_advisories: false
      background_sync: false
      sync_interval: "6h"
```

`on_error: block` and `on_stale: block` fail closed by default. Missing,
corrupt, incomplete, unhealthy, or stale local data blocks OSV checks instead of
silently allowing installs. `background_sync: true` runs an immediate sync in
the background and repeats it after `sync_interval`; a valid non-stale database
remains available while it refreshes. Missing or stale data keeps readiness and
default fail-closed policy checks unavailable until synchronization succeeds.
With `background_sync: false`, no automatic OSV sync runs at boot.
`retain_raw_advisories` defaults to false so the SQLite database stores compact
normalized lookup data by default; set it to true only when you need raw OSV
advisory JSON for audit or debugging.

For fast boot, run `osv sync` in CI or an init/deployment step and ship the
completed SQLite file with the service. A preseeded, non-stale database is ready
immediately; enable `background_sync` when automatic refresh at process start
is desired. Do not place a live, actively-updated SQLite file in an image
layer; preseed a complete file, then refresh it outside the serving process.

## Performance

Local OSV evaluation is designed to stay close to the policy-disabled path:
the measured p50 overhead was about 2–7 ms for representative npm, Go, and
Cargo routes, with higher-cardinality NuGet, RubyGems, PyPI, and Maven routes
adding more. A full local database is about 195 MiB and a fresh sync takes
about 21 seconds with roughly 221 MiB peak RSS on the reference machine.

Live mode is substantially slower because it waits on remote OSV batch queries;
large metadata requests can take several seconds.
For the complete matrix, resource measurements, and fast-boot deployment
patterns, see [Performance and fast boot](docs/performance.md).

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

Run Rust unit tests without external package managers:

```sh
cargo test --locked --lib
```

This is a partial verification command. The required fully provisioned suite is
`cargo test --locked`; missing external tools intentionally fail rather than
skip.

Run only the route-level policy flow tests:

```sh
cargo test --locked e2e
```

Run only the package-manager end-to-end tests. These start local fixture
registries and a local proxy, then run npm, uv/pip, Cargo, Go, .NET, Bundler,
Maven, and Gradle clients against the proxy:

```sh
cargo test --locked --test package_manager_e2e
```

The full local toolchain matches required CI: Rust 1.97.0; Temurin Java
21.0.7+6, Maven 3.9.11, and Gradle 8.14.3; .NET SDK 8.0.128; Node 24.18.0 and
npm; Go 1.24.0; Ruby 3.3.8 with `gem` and Bundler 2.5.23; uv 0.11.28; plus
`zip` and `shasum`. Every corresponding command (`java`, `mvn`, `gradle`,
`dotnet`, `node`/`npm`, `go`, `ruby`/`gem`/`bundle`, `uv`, `cargo`, `zip`, and
`shasum`) must be available on `PATH`.

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
- [Performance and fast boot](docs/performance.md)
- [Architecture notes](docs/architecture.md)
- [Milestones](docs/milestones.md)
