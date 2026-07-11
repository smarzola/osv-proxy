# Client Configuration

These examples assume `osv-proxy` is listening at `http://127.0.0.1:8080`.

## Cargo / crates.io

```toml
[source.crates-io]
replace-with = "osv-proxy"
[source.osv-proxy]
registry = "sparse+http://127.0.0.1:8080/cargo/"
```

This is read-only sparse source replacement, not publishing or a private registry.

## npm

```sh
npm config set registry http://127.0.0.1:8080/npm/
```

## pnpm

```sh
pnpm config set registry http://127.0.0.1:8080/npm/
```

## pip

```sh
pip config set global.index-url http://127.0.0.1:8080/pypi/simple/
```

## uv

```sh
uv pip install --index-url http://127.0.0.1:8080/pypi/simple/ requests
```

## poetry

```sh
poetry source add osv-proxy http://127.0.0.1:8080/pypi/simple/
```

## Go modules

```sh
export GOPROXY=http://127.0.0.1:8080/go
export GONOSUMDB='*'
```

Use one proxy URL when this is a mandatory policy control. Appending `,direct`
or another proxy allows fallback after `404`/`410` and can bypass the gate.
Policy denials are `403`, deliberately terminal for Go proxy fallback.

## .NET / NuGet

```sh
dotnet restore --source http://127.0.0.1:8080/nuget/v3/index.json
```

NuGet support is restore-scoped; search, publishing, symbols, and
authentication are unsupported.

## Ruby / Bundler

Use the proxy as the only source in `Gemfile`:

```ruby
source "http://127.0.0.1:8080/rubygems/"
```

Then run `bundle install` normally. Do not configure a fallback mirror or an
additional public source when the proxy is a mandatory policy gate. Support is
limited to modern Bundler Compact Index restore; legacy RubyGems Marshal
indexes, standalone `gem install`, search, publishing, yanking, authentication,
and private registry hosting are unsupported.

## Java / Maven

Configure a mirror in Maven `settings.xml`:

```xml
<mirrors>
  <mirror>
    <id>osv-proxy</id>
    <url>http://127.0.0.1:8080/maven/</url>
    <mirrorOf>*</mirrorOf>
  </mirror>
</mirrors>
```

`mirrorOf` must cover every repository when the proxy is a mandatory gate.
Maven can otherwise resolve through repositories declared by projects or
plugins. Existing files in the local Maven cache are not revalidated; use a
clean repository or force refresh when testing a new denial.

## Java / Gradle

Use the proxy as the sole Maven repository and centralize repository policy in
`settings.gradle`:

```groovy
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { maven { url = uri("http://127.0.0.1:8080/maven/") } }
}
```

Do not also declare Maven Central or another public repository: Gradle can fall
back to it after a miss. Existing Gradle cache entries cannot be revoked by the
proxy, so refresh or isolate the cache when validating policy changes.

Maven support is read-only and release-only. Snapshots, private-repository
authentication, publishing, search, and multi-repository aggregation are not
supported.
