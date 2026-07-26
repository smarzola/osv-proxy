# Manage OSV advisory data

`osv-proxy` evaluates OSV policy from local SQLite. It synchronizes advisory
data for npm, PyPI, Go, crates.io, NuGet, RubyGems, and Maven.

Run synchronization before the first server start:

```sh
osv-proxy config validate --config /path/to/osv-proxy.yaml
osv-proxy osv sync --config /path/to/osv-proxy.yaml
```

`malicious sync` remains a compatibility alias. New automation should use
`osv sync`.

## Understand the stored data

The compact schema stores the following data:

- Advisory identifiers, modification state, and withdrawal state.
- Normalized affected ecosystems and package names.
- Exact affected versions.
- Range types and ordered range events.
- Selected severity type, vector, base score, or evaluation error.
- Per-ecosystem generation, health, source timestamp, and content revision.

Set `retain_raw_advisories: true` only when you need the full source JSON for
audit or debugging. The default value is `false`.

The reference all-ecosystem database measured about 195 MiB without raw JSON.
Allow additional disk capacity for dataset growth and SQLite write-ahead-log
activity.

## Understand bootstrap and incremental sync

A bootstrap performs the following steps:

1. Downloads and validates the ecosystem archive.
2. Imports records into a staging generation.
3. Catches up changes published near the archive boundary.
4. Activates the complete generation in one transaction.

A failed bootstrap rolls back and leaves the previous active generation
unchanged.

An incremental sync reads changes after the consumed OSV source timestamp.
Rows at the exact high-watermark timestamp replay safely so that equal
timestamps cannot hide distinct records. Changed advisory data replaces the
normalized rows in one transaction.

Each requested ecosystem succeeds or fails independently. A failure in one
ecosystem does not prevent another ecosystem from committing a healthy update.

## Understand cache invalidation

Each ecosystem has a monotonically increasing content revision. A transaction
advances it only when normalized advisory content changes.

The filtered metadata cache includes the revision in its key. After a
content-changing commit, a new request cannot use metadata filtered at the
previous revision. No-op and failed syncs preserve the revision.

## Run background synchronization

The default server configuration enables background sync:

```yaml
policy:
  osv:
    local:
      background_sync: true
      sync_interval: "1h"
```

The server starts one update immediately without waiting for it. A complete,
non-stale database remains ready while an incremental update runs. Missing,
incomplete, unhealthy, or stale data remains unready until a successful sync
satisfies policy.

A fully successful cycle waits for `sync_interval` before it starts the next
cycle. Failed ecosystems retry independently with bounded exponential backoff
from five seconds through five minutes.

Set `background_sync: false` only when another component reliably owns
synchronization.

## Preseed the database

Preseed the database when startup must not depend on OSV network availability:

```sh
mkdir -p /var/lib/osv-proxy
osv-proxy config validate --config /etc/osv-proxy/osv-proxy.yaml
osv-proxy osv sync --config /etc/osv-proxy/osv-proxy.yaml
osv-proxy serve --config /etc/osv-proxy/osv-proxy.yaml
```

Run the sync in CI, an image-build job, or a deployment init job. Ship or mount
the completed database only after the sync process exits.

Do not copy a SQLite database while another process writes it. SQLite
write-ahead logging allows live readers to continue using the last committed
generation, but a filesystem copy must also account for active WAL state.

## Prevent concurrent syncs

Only one explicit or background sync can operate on a SQLite path at a time.
The process holds an advisory lock on the adjacent
`<sqlite_path>.sync.lock` file for the entire run. A concurrent process fails
instead of interleaving writes.

## Handle stale or invalid data

The default failure posture is:

```yaml
policy:
  osv:
    on_error: "block"
    local:
      max_staleness: "24h"
      on_stale: "block"
```

Missing, corrupt, unhealthy, incomplete, or stale data fails closed. `/readyz`
reports each ecosystem separately and returns HTTP `503` if any required
dataset is not ready.

An upgraded malicious-only database has dataset version zero. It cannot
produce a clean vulnerability result until an all-advisory bootstrap
succeeds.

An exact allowlist entry with `bypass_osv: true` skips both malicious and
vulnerability checks for that version.
