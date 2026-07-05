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
}

pub enum DecisionReason {
    Allowed,
    Allowlisted,
    TooYoung,
    Malicious,
    ManuallyBlocked,
    MissingPublishTime,
    Unknown,
}
```

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

## Evaluation Order

1. Build canonical `Artifact`.
2. Check exact-version allowlist.
3. If allowlist has `bypass_malicious=true`, skip malicious check.
4. Otherwise check malicious package source.
5. If malicious, block.
6. Check manual local blocklist.
7. If manually blocked, block.
8. If allowlist has `bypass_age_gate=true`, skip age gate.
9. Otherwise apply minimum age gate.
10. If package is too young, block.
11. If publish time is missing, follow `missing_publish_time` config.
12. Otherwise allow.

Allowlist entries are exact-version only.

## Allowlist

Allowed:

```yaml
allowlist:
  - ecosystem: npm
    name: lodash
    version: "4.17.21"
    bypass_age_gate: true
    bypass_malicious: false
    reason: "Known safe old version"
```

Not supported:

```yaml
allowlist:
  - ecosystem: npm
    name: lodash
    version: "*"
```

Bypassing malicious package blocks must be explicit and require a reason.

```yaml
allowlist:
  - ecosystem: npm
    name: some-package
    version: "1.2.3"
    bypass_age_gate: true
    bypass_malicious: true
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

## Malicious Package Blocking

By default, only OSV IDs starting with `MAL-` are considered malicious.

Classification:

- `MAL-*`: malicious
- CVEs, GHSAs, and other vulnerabilities: ignored for blocking by default

OSV is checked during policy evaluation. The default OSV API URL is
`https://api.osv.dev`; override `policy.osv.api_url` only when routing through a
mirror, fixture, or private gateway.

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
