# Client Configuration

These examples assume `osv-proxy` is listening at `http://127.0.0.1:8080`.

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

## .NET / NuGet

Use the restore-scoped V3 service index as the only package source:

```sh
dotnet restore --source http://127.0.0.1:8080/nuget/v3/index.json
```

The proxy supports registration and flat-container restore resources only;
NuGet search, publishing, symbols, and authentication are not available.
