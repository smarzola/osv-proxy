# osv-proxy

`osv-proxy` is a read-only package-registry security proxy that combines the
[OSV vulnerability database](https://osv.dev/) with local policy. It filters
registry metadata before dependency resolution and checks policy again before
it redirects or proxies package files.

Use `osv-proxy` when you want one policy gate for npm, PyPI, Cargo, Go modules,
NuGet, RubyGems, or Maven Central without adding OSV network calls to package
install requests.

## How it works

For a metadata request, `osv-proxy` does the following:

1. Fetches and validates metadata from the public registry or your configured
   upstream.
2. Removes package versions that fail OSV, minimum-age, allowlist, or blocklist
   policy.
3. Rewrites retained download URLs so that package files return through the
   proxy for a second policy check.

The proxy evaluates OSV policy from a synchronized local SQLite database. It
does not call the OSV query API while serving registry, `check`, or `eval`
requests.

Supported metadata responses use a bounded in-process cache. A cache hit skips
the upstream fetch, parsing, SQLite policy evaluation, filtering, and
serialization. Package files never enter this cache and always receive the
delivery-time policy check.

## Supported package managers

| Ecosystem | Clients and protocol | Metadata and file behavior |
| --- | --- | --- |
| Cargo | Cargo sparse registry | Filters index records; protects `.crate` files |
| Go | `GOPROXY` | Filters version discovery; protects `.info`, `.mod`, and `.zip` |
| Maven | Maven and Gradle | Filters release metadata; protects POMs, JARs, modules, classifiers, signatures, and checksums |
| npm | npm, pnpm, Yarn, and Bun | Filters package metadata; protects tarballs |
| NuGet | `dotnet restore` and NuGet V3 | Filters registration and version indexes; protects `.nupkg` and `.nuspec` files |
| PyPI | pip, uv, and Poetry | Filters Simple JSON and HTML; protects distribution files |
| RubyGems | Modern Bundler Compact Index | Filters gem versions; protects `.gem` files |

`osv-proxy` does not implement publishing, authentication, search, private
registry hosting, license policy, S3 artifact caching, Maven snapshots, or
legacy RubyGems indexes.

## Install osv-proxy

Download an archive and `SHA256SUMS` from
[GitHub Releases](https://github.com/smarzola/osv-proxy/releases). Release
archives use the following names:

```text
osv-proxy-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
osv-proxy-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz
osv-proxy-vX.Y.Z-x86_64-apple-darwin.tar.gz
osv-proxy-vX.Y.Z-aarch64-apple-darwin.tar.gz
```

To build from source, run:

```sh
cargo build --release --locked
```

## Start the proxy

The repository includes a working local configuration. Validate it, populate
the OSV database, and start the server:

```sh
mkdir -p data
osv-proxy config validate --config examples/basic/osv-proxy.yaml
osv-proxy osv sync --config examples/basic/osv-proxy.yaml
osv-proxy serve --config examples/basic/osv-proxy.yaml
```

Preseeding the database makes startup independent of OSV network availability.
The default background task then starts an incremental update immediately and
starts each later update one hour after the previous successful cycle.

Check liveness and readiness:

```sh
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

`/healthz` reports process liveness. `/readyz` returns HTTP `200` only when all
seven OSV datasets satisfy health, completeness, and staleness requirements.

## Configure a package manager

The following examples use `http://127.0.0.1:8080`.

Configure npm:

```sh
npm config set registry http://127.0.0.1:8080/npm/
```

Configure pip:

```sh
pip config set global.index-url http://127.0.0.1:8080/pypi/simple/
```

Configure Cargo in `.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "osv-proxy"

[source.osv-proxy]
registry = "sparse+http://127.0.0.1:8080/cargo/"
```

Configure Go:

```sh
export GOPROXY=http://127.0.0.1:8080/go
export GONOSUMDB='*'
```

Do not append `,direct` or another proxy when `osv-proxy` must enforce policy.
Go can use those fallbacks after an upstream `404` or `410`.

For NuGet, Bundler, Maven, Gradle, pnpm, uv, and Poetry instructions, see
[Configure package-manager clients](docs/client-configuration.md).

## Configure security policy

The example configuration uses the following security posture:

```yaml
metadata_cache:
  enabled: true
  capacity_bytes: 134217728
  max_entry_bytes: 16777216
  ttl: "5m"
  fill_concurrency: 8

policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    on_error: "block"
    local:
      sqlite_path: "./data/osv-malicious.sqlite"
      max_staleness: "24h"
      on_stale: "block"
      retain_raw_advisories: false
      background_sync: true
      sync_interval: "1h"

artifacts:
  behavior: "redirect"
```

These defaults have the following effects:

- A package version must be at least 72 hours old.
- Missing publication times fail closed.
- Matching `MAL-*` records block as malicious.
- Other matching OSV advisories block at an inclusive CVSS threshold of zero.
  At zero, matching unscored advisories also block.
- OSV lookup failures and stale local data fail closed.
- Complete filtered metadata responses use a 128 MiB weighted cache with a
  16 MiB body limit, a five-minute maximum lifetime, and eight concurrent
  distinct fills.
- Allowed package files return an HTTP `302` redirect after the second policy
  check.

Set `policy.osv.block_vulnerabilities: false` if you want to block only OSV
malicious-package records. Set `artifacts.behavior: proxy` if clients must
receive package bytes through `osv-proxy`.

See the [configuration reference](docs/configuration.md) for every field and
validation rule. See the [policy reference](docs/policy.md) for evaluation
order and decision semantics.

## Keep OSV data current

Run an explicit update at any time:

```sh
osv-proxy osv sync --config /path/to/osv-proxy.yaml
```

The command bootstraps missing or incomplete ecosystems and incrementally
updates complete ones. Each ecosystem commits independently, and a failed
import never replaces its last healthy generation.

A content-changing commit also advances that ecosystem's durable revision.
New metadata requests then use a new cache key and cannot receive a response
filtered against older OSV content. No-op and failed syncs leave the revision
unchanged.

Set `background_sync: false` only when CI, an init job, or another deployment
component owns synchronization. For database lifecycle and failure semantics,
see [Manage OSV advisory data](docs/osv-data.md).

## Check a package from the command line

`check` fetches registry metadata and evaluates the same canonical artifact
data used by proxy routes:

```sh
osv-proxy check npm:lodash@4.17.21 \
  --config examples/basic/osv-proxy.yaml
```

Supported identities include:

```text
npm:@babel/core@7.24.0
pypi:requests@2.32.3
cargo:serde@1.0.219
go:github.com/pkg/errors@v0.9.1
nuget:Newtonsoft.Json@13.0.3
rubygems:rails@8.0.2
maven:org.apache.commons:commons-lang3@3.17.0
```

`check` exits nonzero if required upstream metadata is missing or malformed.
Use `eval` only when you intentionally want to supply synthetic artifact
fields:

```sh
osv-proxy eval npm:example@1.2.3 \
  --config examples/basic/osv-proxy.yaml \
  --published-at 2026-06-01T00:00:00Z
```

## Deploy safely

The default listener is loopback-only. For a shared deployment, place
`osv-proxy` behind a trusted gateway or reverse proxy that provides TLS,
authentication, client rate limiting, and edge access control.

`osv-proxy` provides process-wide ingress and outbound-request budgets, local
readiness, and graceful shutdown. It does not replace an internet-facing
gateway. See [Configure osv-proxy](docs/configuration.md) and
[Understand the architecture](docs/architecture.md) before exposing a shared
service.

## Develop and verify

Run the repository checks:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo run --locked -- config validate \
  --config examples/basic/osv-proxy.yaml
```

The full test suite invokes npm, uv/pip, Cargo, Go, .NET, Bundler, Maven, and
Gradle against hermetic local registries. CI installs the required client
toolchains.

## Documentation

- [Configure osv-proxy](docs/configuration.md)
- [Configure package-manager clients](docs/client-configuration.md)
- [Understand policy decisions](docs/policy.md)
- [Review registry and HTTP behavior](docs/registry-behavior.md)
- [Manage OSV advisory data](docs/osv-data.md)
- [Plan performance and startup](docs/performance.md)
- [Understand the architecture](docs/architecture.md)
- [Monitor the service](docs/observability.md)
- [Review product scope and invariants](docs/product-spec.md)
- [Review support status and roadmap](docs/milestones.md)

## License

`osv-proxy` is licensed under the Apache License, Version 2.0. OSV advisories
and upstream vulnerability records retain their source licenses and
attribution requirements when you cache, export, or redistribute them.
