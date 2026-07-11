# OSV Advisory Data

`osv-proxy` evaluates active OSV records for npm, PyPI, Go, crates.io, NuGet,
RubyGems, and Maven. `MAL-*` records are classified as known malicious packages. Other IDs
are vulnerabilities and are evaluated against `policy.osv.minimum_cvss_score`.

Live mode queries OSV during metadata filtering and repeats the check before an
artifact redirect or proxy fetch. Batch metadata queries hydrate advisory
details with at most 16 concurrent requests, deduplicate repeated IDs, and
preserve one result per requested version.

Local mode performs no OSV network request on the install path. Populate it
with the canonical command:

```sh
osv-proxy osv sync --config /path/to/osv-proxy.yaml
```

`malicious sync` remains a compatibility alias. Bootstrap imports all supported
advisory IDs into a staging generation, catches up changes published alongside
the archive, and atomically activates the complete generation. Incremental sync
uses only consumed OSV source timestamps. An upgraded malicious-only database
is marked version 0 and cannot return a clean vulnerability result until this
full bootstrap succeeds.

Each sync run attempts all seven ecosystems and reports successes and failures
separately, so an early failure does not prevent later generation updates.
Only one explicit or background run may operate on a SQLite store at a time,
including across processes; a sidecar advisory lock is held for the full run.
Background sync retries only failed ecosystems with bounded exponential backoff;
a fully successful cycle waits for the configured normal interval.

The compact schema stores advisory metadata, affected occurrences, exact
versions, ranges/events, and each occurrence's selected severity type, original
vector, base score, or evaluation error. Raw source JSON is retained only when
`retain_raw_advisories: true`. Repeated `affected[]` entries remain independent.
Exact and range findings are unioned and withdrawn advisories are excluded.

Full advisory storage is materially larger than the former `MAL-*`-only store.
The 2026-07-11 pre-Maven measurement was 168,296,448 bytes without raw
JSON, versus a 92,114,944-byte npm-plus-PyPI malicious-only baseline. Plan disk
capacity for the additional Maven dataset, ongoing dataset growth, and SQLite
WAL activity during sync.

Missing, corrupt, unhealthy, incomplete, or stale data follows `on_error` and
`local.on_stale`; both block by default. A failed staging import rolls back and
does not expose partial data. Exact allowlist entries with `bypass_osv: true`
skip both malicious and vulnerability checks.
