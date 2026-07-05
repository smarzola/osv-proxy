# osv-proxy

`osv-proxy` is a Rust package registry security proxy for npm and PyPI.

It sits between package managers and public registries, filters package metadata through deterministic policy, and rechecks policy before artifact downloads. The goal is a boring, reliable package registry firewall: no package version should be installable unless `osv-proxy` currently considers it allowed.

## Core Value

- Do not install package versions that are too new.
- Do not install packages known to be malicious through OSV `MAL-*` records.
- Allow explicit, audited exact-version exceptions.
- Keep public-service artifact egress low by redirecting downloads upstream by default.

## First Supported Ecosystems

- npm
- PyPI

The architecture should allow future adapters for Maven, RubyGems, crates.io, Go modules, Docker/OCI, NuGet, Composer, and other registries.

## Planned Commands

```sh
osv-proxy serve --config osv-proxy.yaml
osv-proxy check npm:lodash@4.17.21 --config osv-proxy.yaml
osv-proxy sync-malicious --config osv-proxy.yaml
osv-proxy config validate --config osv-proxy.yaml
```

## V1 Scope

Required for v1:

- Rust implementation
- YAML local configuration
- npm support
- PyPI support
- built-in malicious package blocking from OSV
- minimum package age gate
- manual blocklist
- exact-version allowlist
- OSV malicious lookup modes: naive and local
- local malicious mode backed by MongoDB-compatible storage
- mongolino support for simple single-file local deployments
- metadata cache disabled or cachebox-backed only
- artifact behavior: redirect, proxy, and proxy with S3-compatible cache
- structured audit logs
- clear HTTP 403 error responses

Not in v1:

- web UI
- private package publishing
- package vulnerability severity policy
- license policy
- SBOM ingestion
- STIX/CSAF exports
- user authentication
- admin API
- machine learning risk scoring
- automatic package source-code scanning

## Documentation

- [Product Specification](docs/product-spec.md)
- [Architecture](docs/architecture.md)
- [Policy Model](docs/policy.md)
- [Configuration](docs/configuration.md)
- [Registry Behavior](docs/registry-behavior.md)
- [Milestones](docs/milestones.md)
- [Client Configuration](docs/client-configuration.md)

## Implementation Status

This repository is currently documentation-only. No Rust workspace or source code has been created yet.
