# Find OSV malicious-package data guidance

The local SQLite database stores all supported OSV advisories, not only
malicious-package records.

Read [Manage OSV advisory data](osv-data.md) for the data model,
synchronization commands, readiness rules, and failure behavior.

OSV `MAL-*` records remain independently controlled by
`policy.osv.block_malicious` and take precedence over vulnerability findings.
The `malicious sync` command remains a compatibility alias for `osv sync`.
