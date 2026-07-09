# OSV Malicious Records

`osv-proxy` blocks known malicious packages using OSV records whose IDs start
with `MAL-`. CVEs, GHSAs, and general vulnerability advisories are ignored for
blocking because they are not package-malicious decisions.

Cargo uses the exact OSV ecosystem `crates.io`; local sync health and range
evaluation are independent from npm and PyPI.

## Sources

`policy.osv.source: live` calls the OSV API during policy evaluation:

- `POST /v1/query`
- `POST /v1/querybatch`

`policy.osv.source: local` reads synchronized SQLite data instead. Local mode
does not call OSV during install request handling; metadata filtering, artifact
serving, `check`, and `eval` use bounded SQLite reads plus in-memory version
evaluation.

Populate or refresh the local database with:

```sh
osv-proxy malicious sync --config /path/to/osv-proxy.yaml
```

The sync command bootstraps npm and PyPI from OSV GCS `all.zip` dumps, then uses
`modified_id.csv` and per-advisory JSON for incremental updates after a
successful bootstrap. `serve` can run the same sync engine in the background
when `policy.osv.local.background_sync: true`.

## SQLite Storage

The local store keeps advisory metadata and normalized affected clauses. It does
not pre-expand ranges into every concrete npm or PyPI version. Full raw OSV
advisory JSON is optional and disabled by default with
`policy.osv.local.retain_raw_advisories: false`.

Tables:

- `advisories`: OSV ID, modified/published/withdrawn timestamps, summary,
  source, import timestamp, and optional raw JSON. When raw retention is
  disabled, the compatibility column stores a compact empty JSON object.
- `affected_packages`: one row per affected advisory package, indexed by
  ecosystem and normalized package name.
- `affected_versions`: exact OSV `affected[].versions` entries.
- `affected_ranges`: OSV range type for an affected package.
- `affected_range_events`: ordered `introduced`, `fixed`, `last_affected`, and
  `limit` events for a range.
- `sync_state`: ecosystem, source, high-water mark, last successful sync, last
  attempted sync, health status, and error summary.

Withdrawn advisories remain represented as advisory metadata records but do not
keep blocking affected rows.

## Evaluation

Local checks query by ecosystem and normalized package name, then evaluate the
requested version in memory:

1. Exact affected versions match by string equality.
2. npm `SEMVER` ranges are evaluated with npm semver rules.
3. PyPI `ECOSYSTEM` ranges are evaluated with Python package-version rules.
4. Unsupported range types or unevaluable target/boundary versions are checker
   errors.

Only matching `MAL-*` advisories are returned to policy as malicious hits.
Exact allowlist entries with `bypass_osv: true` still skip malicious checks.

## Sync And Failure Behavior

SQLite connections use WAL mode and a busy timeout so sync writes and request
reads can overlap under normal SQLite writer contention. Advisory replacement
and per-ecosystem sync-state advancement are transactional: a failed sync keeps
the previous good snapshot usable and records the failed attempt in
`sync_state`.

Local mode fails closed by default. With `policy.osv.on_error: block` and
`policy.osv.local.on_stale: block`, missing, stale, corrupt, unhealthy, or
unevaluable local data blocks the malicious check instead of silently allowing
an install.
