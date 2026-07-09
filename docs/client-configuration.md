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
