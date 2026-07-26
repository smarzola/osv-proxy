# Configure package-manager clients

This guide configures supported clients to use an `osv-proxy` server at
`http://127.0.0.1:8080`. Replace that URL with your deployment URL.

When the proxy is a mandatory policy gate, configure it as the only public
package source. Client fallbacks and existing local package caches can bypass
new policy decisions.

## Configure Cargo

Add the following source replacement to `.cargo/config.toml`:

```toml
[source.crates-io]
replace-with = "osv-proxy"

[source.osv-proxy]
registry = "sparse+http://127.0.0.1:8080/cargo/"
```

This configuration provides read-only crates.io sparse-source replacement. It
does not provide publishing or private registry hosting.

## Configure npm

```sh
npm config set registry http://127.0.0.1:8080/npm/
```

## Configure pnpm

```sh
pnpm config set registry http://127.0.0.1:8080/npm/
```

## Configure pip

```sh
pip config set global.index-url http://127.0.0.1:8080/pypi/simple/
```

## Configure uv

```sh
uv pip install \
  --index-url http://127.0.0.1:8080/pypi/simple/ \
  requests
```

## Configure Poetry

```sh
poetry source add osv-proxy http://127.0.0.1:8080/pypi/simple/
```

## Configure Go modules

```sh
export GOPROXY=http://127.0.0.1:8080/go
export GONOSUMDB='*'
```

Do not append `,direct` or another public proxy when `osv-proxy` must enforce
policy. Go can use a fallback after an upstream `404` or `410`. The proxy
returns `403` for policy denials so that Go treats the denial as terminal.

Keep mandatory-gate modules out of `GONOPROXY` and `GOPRIVATE`.

## Configure NuGet

Use the proxy service index as the only restore source:

```sh
dotnet restore \
  --source http://127.0.0.1:8080/nuget/v3/index.json
```

NuGet support covers restore. It does not cover search, publishing, deletion,
symbols, authentication, or private registry hosting.

## Configure Bundler

Use the proxy as the only source in `Gemfile`:

```ruby
source "http://127.0.0.1:8080/rubygems/"
```

Then run `bundle install`. Do not configure a public fallback source when the
proxy must enforce policy.

RubyGems support targets modern Bundler Compact Index restore. It does not
support legacy Marshal indexes, standalone `gem install`, search, publishing,
yanking, authentication, or private gem hosting.

## Configure Maven

Add a mirror to Maven `settings.xml`:

```xml
<mirrors>
  <mirror>
    <id>osv-proxy</id>
    <url>http://127.0.0.1:8080/maven/</url>
    <mirrorOf>*</mirrorOf>
  </mirror>
</mirrors>
```

Use `mirrorOf` value `*` when the proxy must cover every repository. Maven can
otherwise resolve through repositories declared by projects or plugins.

Existing files in the local Maven repository do not return through the proxy.
Use a clean repository or force a refresh when you test a new denial.

## Configure Gradle

Declare the proxy as the only Maven repository and enforce repository policy
in `settings.gradle`:

```groovy
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven {
            url = uri("http://127.0.0.1:8080/maven/")
        }
    }
}
```

Do not also declare Maven Central or another public repository. Gradle can use
that repository after a miss. Refresh or isolate the Gradle cache when you
test policy changes.

Maven support is read-only and release-only. It does not support snapshots,
private-repository authentication, publishing, search, or aggregation across
multiple repositories.
