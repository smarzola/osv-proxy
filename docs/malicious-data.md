# Malicious Data

`osv-proxy` blocks known malicious packages using OSV records.

For v1, only OSV IDs starting with `MAL-` are considered malicious. CVEs, GHSAs, and general vulnerability advisories are ignored for blocking by default.

## Naive Mode

Naive mode queries OSV APIs directly during policy evaluation.

Endpoints:

- `POST /v1/query`
- `POST /v1/querybatch`

Config:

```yaml
policy:
  malicious:
    mode: "naive"
    only_mal_ids: true
    osv_api_url: "https://api.osv.dev"
    on_osv_error: "block"
```

Naive mode is useful for initial development, smoke tests, small installations, and debugging. It is not ideal for production because OSV latency and availability are in the install path.

## Local Mode

Local mode checks a local MongoDB-compatible store containing malicious package records. It supports:

- `mongolino`
- MongoDB

mongolino should be the default local backend for simple deployments. MongoDB should be supported for multi-instance or production deployments.

The policy engine must not know which backend is used.

```rust
#[async_trait]
pub trait MaliciousPackageStore {
    async fn is_malicious(&self, artifact: &Artifact) -> Result<Option<MaliciousHit>>;
}
```

Suggested hit model:

```rust
pub struct MaliciousHit {
    pub osv_id: String,
    pub summary: Option<String>,
    pub source: String,
    pub modified: Option<DateTime<Utc>>,
}
```

## Document Shape

```json
{
  "ecosystem": "npm",
  "name": "some-package",
  "version": "1.2.3",
  "osv_id": "MAL-2026-000001",
  "summary": "Malicious package",
  "modified": "2026-07-05T12:00:00Z",
  "source": "osv",
  "inserted_at": "2026-07-05T12:05:00Z"
}
```

Indexes:

- unique index: `ecosystem + name + version + osv_id`
- lookup index: `ecosystem + name + version`

## Background Sync

1. Fetch OSV malicious package data.
2. Keep only records with IDs starting with `MAL-`.
3. Keep only npm and PyPI for v1.
4. Normalize ecosystem and package names.
5. Extract affected exact versions.
6. Upsert into MongoDB-compatible store.
7. Record last successful sync timestamp.

The first implementation can use OSV database dumps for full sync. Incremental sync can be added later.
