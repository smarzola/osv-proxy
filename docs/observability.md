# Monitor the service

`osv-proxy` currently exposes health, readiness, and process messages. It does
not yet expose structured request logs or a metrics endpoint.

## Check liveness

Request dependency-free process liveness:

```sh
curl --fail http://127.0.0.1:8080/healthz
```

A live process returns HTTP `200`:

```json
{"live":true}
```

`/healthz` remains outside the ingress request budget so it can respond during
registry saturation.

## Check readiness

Request local OSV readiness:

```sh
curl http://127.0.0.1:8080/readyz
```

`/readyz` evaluates all seven ecosystems. It requires each active generation
to satisfy health, dataset-version, completeness, and staleness policy.

A ready response returns HTTP `200`. An unready or ingress-saturated response
returns HTTP `503`. Saturation also includes `Retry-After: 1`.

```json
{
  "ready": false,
  "osv_source": "local",
  "ecosystems": [
    {
      "ecosystem": "npm",
      "ready": true
    },
    {
      "ecosystem": "Maven",
      "ready": false,
      "message": "local malicious data for ecosystem Maven is stale"
    }
  ]
}
```

The actual response contains one entry for every supported ecosystem.

## Review process messages

The process emits plain-text messages for the following events:

- A non-loopback listener warning.
- Initial and scheduled OSV sync outcomes.
- Per-ecosystem sync failures and retries.
- Signal-handler setup failures.
- A forced graceful-shutdown drain timeout.

Treat readiness as the machine-readable OSV health source. Process messages
provide operational context but do not replace structured telemetry.

## Planned telemetry

Structured request logs, request identifiers, latency and upstream metrics,
cache metrics, and a metrics exporter are not implemented.

If telemetry is added, it should distinguish metadata from package-file
requests and include the following dimensions where they apply:

- Ecosystem, package, version, and route type.
- Policy decision, reason, source, rule identifier, and CVSS score.
- Upstream status and request duration.
- Cache hit, miss, fill, bypass, and non-retention outcomes.
- Artifact behavior.
- OSV sync mode, ecosystem, imported or withdrawn count, and failure state.

Candidate metric names include:

- `osv_proxy_artifact_requests_total`
- `osv_proxy_blocked_by_reason_total`
- `osv_proxy_metadata_cache_hits_total`
- `osv_proxy_metadata_cache_misses_total`
- `osv_proxy_metadata_requests_total`
- `osv_proxy_osv_sync_last_success_timestamp`
- `osv_proxy_osv_sync_records_total`
- `osv_proxy_policy_decisions_total`

These names describe a future contract. Do not configure monitors against them
until the application exposes them.
