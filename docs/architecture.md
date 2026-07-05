# Architecture

The first implementation should stay pragmatic. Splitting into crates is useful, but avoid over-engineering before the HTTP and policy paths are working.

## Suggested Workspace Layout

```text
osv-proxy/
  Cargo.toml
  crates/
    osv-proxy/
      src/main.rs
    osv-core/
      src/
        artifact.rs
        config.rs
        decision.rs
        ecosystem.rs
        policy.rs
        version.rs
    osv-adapters/
      src/
        npm.rs
        pypi.rs
        mod.rs
    osv-malicious/
      src/
        osv_client.rs
        naive.rs
        local.rs
        mongolino.rs
        mongo.rs
        sync.rs
        store.rs
    osv-metadata-cache/
      src/
        cache.rs
        noop.rs
        cachebox.rs
    osv-artifacts/
      src/
        redirect.rs
        proxy.rs
        s3_cache.rs
    osv-audit/
      src/lib.rs
```

This is a target layout, not current repository state.

## Major Components

```text
osv-proxy
  server
    npm routes
    pypi routes
  adapters
    npm adapter
    pypi adapter
  policy
    age gate
    malicious package check
    manual blocklist
    exact-version allowlist
  malicious
    naive OSV API client
    local MongoDB-compatible store
    background OSV sync
  metadata_cache
    disabled/no-op
    cachebox backend
  artifacts
    redirect mode
    proxy mode
    proxy_cache_s3 mode
  config
  audit
  observability
```

## Canonical Artifact Model

The policy engine evaluates canonical artifacts, not raw npm or PyPI metadata.

```rust
pub enum Ecosystem {
    Npm,
    Pypi,
}

pub struct Artifact {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub filename: Option<String>,
    pub upstream_url: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub hashes: ArtifactHashes,
}

pub struct ArtifactHashes {
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub integrity: Option<String>,
}
```

Canonical package identity format:

```text
{ecosystem}:{name}@{version}
```

Examples:

- `npm:lodash@4.17.21`
- `npm:@babel/core@7.24.0`
- `pypi:requests@2.32.3`

## Ecosystem Normalization

npm:

- preserve scoped package names
- examples: `lodash`, `@babel/core`

PyPI:

- normalize according to Python package-name rules
- examples: `Requests` becomes `requests`, `my_package` becomes `my-package`

## External System Boundaries

Use traits for external services:

- OSV client
- malicious package store
- metadata cache
- artifact backend
- audit sink

The policy engine should not know whether malicious data comes from OSV live calls, mongolino, or MongoDB.
