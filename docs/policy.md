# Understand policy decisions

`osv-proxy` evaluates one canonical artifact model across every registry. A
decision records whether the package file is allowed and why.

## Evaluation order

The policy engine evaluates an artifact in the following order:

1. Match an exact-version allowlist entry.
2. Skip OSV only when that entry sets `bypass_osv: true`.
3. Otherwise, check local OSV data.
4. Block a matching `MAL-*` record as `malicious` when malicious blocking is
   enabled.
5. Block another matching advisory as `vulnerable` when it meets the configured
   CVSS threshold.
6. Apply the manual blocklist.
7. Skip the age gate only when the allowlist entry sets
   `bypass_age_gate: true`.
8. Apply the minimum-age and missing-publication-time policy.
9. Allow the artifact when no rule blocks it.

Malicious findings take precedence over vulnerability findings. Manual blocks
take precedence over age decisions.

## Decision response

A decision contains the following fields:

| Field | Description |
| --- | --- |
| `allowed` | Whether policy allows the artifact |
| `reason` | Stable machine-readable reason |
| `package` | Canonical ecosystem, package, and version identity |
| `message` | Human-readable result |
| `rule_id` | Matching allowlist, blocklist, or OSV identifier when present |
| `source` | Decision source when present |
| `published_at` | Registry publication time when known |
| `eligible_at` | Earliest age-gate eligibility time when relevant |
| `cvss_score` | Selected base score for a scored vulnerability |

Optional fields are absent from JSON when they do not apply.

An allowed decision has this form:

```json
{
  "allowed": true,
  "reason": "allowed",
  "package": "npm:lodash@4.17.21",
  "message": "Package version is allowed"
}
```

A malicious-package decision has this form:

```json
{
  "allowed": false,
  "reason": "malicious",
  "package": "npm:some-package@1.2.3",
  "message": "Blocked by OSV malicious package record MAL-2026-000001",
  "rule_id": "MAL-2026-000001",
  "source": "osv"
}
```

A scored vulnerability decision has this form:

```json
{
  "allowed": false,
  "reason": "vulnerable",
  "package": "npm:some-package@1.2.3",
  "message": "Blocked by OSV vulnerability GHSA-abcd-1234 with CVSS base score 9.8",
  "rule_id": "GHSA-abcd-1234",
  "source": "osv",
  "cvss_score": 9.8
}
```

## Configure the minimum-age gate

```yaml
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
```

The age gate follows these rules:

- A version is old enough when `published_at + minimum_age` is no later than
  the evaluation time.
- A younger version receives reason `too_young`.
- A missing publication time follows `missing_publish_time`.
- An exact allowlist entry can bypass the age gate.

Metadata filtering and package-file delivery both apply the age gate. Cached
metadata expires at the earliest contained age transition, even when the
configured cache time to live is longer.

## Configure OSV blocking

```yaml
policy:
  osv:
    block_malicious: true
    block_vulnerabilities: true
    minimum_cvss_score: 0
    on_error: "block"
```

`MAL-*` identifiers represent malicious-package records. Other active
identifiers, including CVEs and GHSAs, represent vulnerabilities.

`minimum_cvss_score` is inclusive. `osv-proxy` selects the highest recognized
CVSS v2, v3, or v4 base score that applies to the matching package occurrence.
A nonempty package-level severity list takes precedence over the top-level
severity list.

Threshold behavior is as follows:

| Advisory | Threshold zero | Positive threshold |
| --- | --- | --- |
| Score meets or exceeds threshold | Block | Block |
| Score is below threshold | Not applicable at zero | Allow |
| No recognized score | Block | Allow |
| Malformed recognized vector | Follow `on_error` | Follow `on_error` |

Set `block_vulnerabilities: false` to retain `MAL-*` blocking without general
vulnerability blocking.

`on_error` applies to SQLite checker failures, missing batch results, and
malformed recognized CVSS vectors. `block` fails closed. `allow` permits that
error but does not override a valid matching finding.

The install path reads synchronized SQLite data and makes no OSV network
request. Policy or revision errors can share a bounded in-flight metadata fill,
but the cache does not retain their results.

## Configure an allowlist

Allowlist entries match one exact version:

```yaml
allowlist:
  - ecosystem: npm
    name: "lodash"
    version: "4.17.21"
    bypass_age_gate: true
    bypass_osv: false
    reason: "Approved version"
```

Use `bypass_osv` only for a reviewed exception:

```yaml
allowlist:
  - ecosystem: npm
    name: "some-package"
    version: "1.2.3"
    bypass_age_gate: false
    bypass_osv: true
    reason: "False positive confirmed internally"
```

An OSV bypass requires a nonempty `reason`. Wildcard allowlist versions are
not supported.

## Configure a manual blocklist

A blocklist entry accepts exact versions or `*`:

```yaml
blocklist:
  - ecosystem: npm
    name: "event-stream"
    versions: ["*"]
    reason: "Blocked after an internal incident"
  - ecosystem: pypi
    name: "example-package"
    versions: ["1.0.0", "1.0.1"]
    reason: "Versions fail internal policy"
```

Version ranges are not supported.

## Understand metadata and file enforcement

Metadata routes remove denied versions before a package manager resolves a
dependency. Retained file URLs point back through `osv-proxy`.

Package-file routes rebuild the requested canonical artifact and evaluate
current policy again. They do not use the metadata cache. A newly synchronized
advisory can therefore block a file even when a client previously received
metadata that advertised it.

The proxy cannot revoke files already stored in a package manager's local
cache.
