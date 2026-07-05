# OSV Malicious Records

`osv-proxy` blocks known malicious packages using OSV records whose IDs start
with `MAL-`. CVEs, GHSAs, and general vulnerability advisories are ignored for
blocking because they are not package-malicious decisions.

## OSV Checks

`osv-proxy` queries OSV during policy evaluation.

Endpoints:

- `POST /v1/query`
- `POST /v1/querybatch`

Config:

```yaml
policy:
  osv:
    on_error: "block"
```

`policy.osv.api_url` is optional. Omit it to use `https://api.osv.dev`; set it
only for a mirror, fixture, or private gateway.

## Stored Records

A future local store should keep the same policy semantics: only `MAL-*` records
are blocking inputs, and the policy engine should not know whether a record came
from live OSV or a synchronized store.

Suggested record shape:

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
