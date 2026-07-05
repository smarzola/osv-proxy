# Observability

Use structured logs and metrics.

## Metadata Request Logs

Each metadata request should log:

- `request_id`
- `ecosystem`
- `package`
- `route_type=metadata`
- `upstream_status`
- `cache_status`
- `versions_total`
- `versions_allowed`
- `versions_blocked`
- `duration_ms`

## Artifact Request Logs

Each artifact request should log:

- `request_id`
- `ecosystem`
- `package`
- `version`
- `filename`
- `route_type=artifact`
- `decision`
- `reason`
- `artifact_behavior`
- `upstream_url`
- `duration_ms`

## Blocked Decision Logs

Each blocked decision should log:

- `ecosystem`
- `package`
- `version`
- `decision=blocked`
- `reason`
- `rule_id`
- `source`
- `message`

## Metrics

- `osv_proxy_metadata_requests_total`
- `osv_proxy_artifact_requests_total`
- `osv_proxy_policy_decisions_total`
- `osv_proxy_blocked_total`
- `osv_proxy_blocked_by_reason_total`
- `osv_proxy_osv_api_requests_total`
- `osv_proxy_osv_api_errors_total`
- `osv_proxy_metadata_cache_hits_total`
- `osv_proxy_metadata_cache_misses_total`
- `osv_proxy_artifact_cache_hits_total`
- `osv_proxy_artifact_cache_misses_total`
- `osv_proxy_malicious_sync_last_success_timestamp`
- `osv_proxy_malicious_sync_records_total`
