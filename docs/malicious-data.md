# OSV Malicious Records (Compatibility Page)

The local store now contains all supported OSV advisories, not only malicious
records. See [OSV advisory data](osv-data.md) for the current data model, sync
command, readiness, storage, and failure semantics.

Existing links to this page remain valid for operators using the `MAL-*`
classification. `MAL-*` records remain independently controlled by
`policy.osv.block_malicious` and take precedence over vulnerability findings.
The old `malicious sync` command remains a compatibility alias for canonical
`osv sync`.
