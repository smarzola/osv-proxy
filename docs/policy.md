# Policy Model

The policy engine decides whether a canonical artifact is installable.

## Decision Model

```rust
pub struct Decision {
    pub allowed: bool,
    pub reason: DecisionReason,
    pub package: String,
    pub message: String,
    pub rule_id: Option<String>,
    pub source: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub eligible_at: Option<DateTime<Utc>>,
    pub cvss_score: Option<f64>,
}

pub enum DecisionReason {
    Allowed,
    Allowlisted,
    TooYoung,
    Malicious,
    Vulnerable,
    ManuallyBlocked,
    MissingPublishTime,
    Unknown,
}
```

Optional fields are omitted from JSON when absent.

Allowed decision:

```json
{
  "allowed": true,
  "reason": "allowed",
  "package": "npm:lodash@4.17.21",
  "message": "Package version is allowed"
}
```

Blocked decision:

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

Scored vulnerability decision:

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

## Evaluation Order

1. Build canonical `Artifact`.
2. Check exact-version allowlist.
3. If allowlist has `bypass_osv=true`, skip OSV check.
4. Otherwise check OSV.
5. If a `MAL-*` record matches and malicious blocking is enabled, block as `malicious`.
6. If another active advisory meets the vulnerability threshold, block as `vulnerable`.
7. Check manual local blocklist.
8. If manually blocked, block.
9. If allowlist has `bypass_age_gate=true`, skip age gate.
10. Otherwise apply minimum age gate.
11. If package is too young, block.
12. If publish time is missing, follow `missing_publish_time` config.
13. Otherwise allow.

Allowlist entries are exact-version only.

## Allowlist

Allowed:

```yaml
allowlist:
  - ecosystem: npm
    name: lodash
    version: "4.17.21"
    bypass_age_gate: true
    bypass_osv: false
    reason: "Known safe old version"
```

Not supported:

```yaml
allowlist:
  - ecosystem: npm
    name: lodash
    version: "*"
```

Bypassing OSV package blocks must be explicit and require a reason.

```yaml
allowlist:
  - ecosystem: npm
    name: some-package
    version: "1.2.3"
    bypass_age_gate: true
    bypass_osv: true
    reason: "False positive confirmed internally"
```

## Minimum Age Gate

Default:

```yaml
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
```

Behavior:

- `published_at + minimum_age <= now` means allowed, subject to other policy.
- `published_at + minimum_age > now` means blocked.
- missing publish time follows `missing_publish_time`, either `block` or `allow`.

The age gate applies during metadata filtering and artifact serving.

## OSV Advisory Blocking

By default, active matching OSV advisories block. `MAL-*` IDs are classified as
malicious and take precedence over vulnerability findings. Other IDs are
classified as vulnerable.

Classification:

- `MAL-*`: malicious
- CVEs, GHSAs, and other advisories: vulnerable

`minimum_cvss_score` is inclusive: a score equal to the threshold blocks. The
matching package's non-empty severity list overrides top-level severity, and
the highest recognized CVSS v2/v3/v4 base score is used. At threshold zero,
unscored matching advisories block. At positive thresholds they do not.
Malformed recognized vectors follow `on_error`. Set
`block_vulnerabilities: false` to preserve malicious-only behavior without
vulnerability detail hydration.

`on_error` applies to checker failures, missing batch results, pagination
failures, and malformed recognized severity vectors. With `block`, policy emits
an OSV error decision; with `allow`, that error does not itself block. This is
separate from a valid OSV finding: a matching finding is evaluated by its
classification and threshold even when other advisory lookups fail.

OSV is checked during policy evaluation. Local SQLite data is the default
source and makes no OSV network request on the install path. Set
`policy.osv.source: live` to query the remote API instead. The default live API
URL is `https://api.osv.dev`; override `policy.osv.api_url` only when routing
through a mirror, fixture, or private gateway.

## Manual Blocklist

```yaml
blocklist:
  - ecosystem: npm
    name: "event-stream"
    versions: ["*"]
    reason: "Known problematic package"
  - ecosystem: pypi
    name: "example-package"
    versions: ["1.0.0", "1.0.1"]
    reason: "Internal incident"
  - ecosystem: npm
    name: "lodash"
    versions: ["<4.17.21"]
    reason: "Legacy versions not allowed"
```

Version ranges can follow after exact-version behavior is stable.
