use crate::artifact::Artifact;
use crate::config::{AllowlistEntry, Config, MissingPublishTime, OsvErrorBehavior};
use crate::malicious::{MaliciousChecker, MaliciousHit};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: DecisionReason,
    pub package: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eligible_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReason {
    Allowed,
    Allowlisted,
    TooYoung,
    Malicious,
    ManuallyBlocked,
    MissingPublishTime,
    Unknown,
}

pub struct PolicyEngine<'a> {
    config: &'a Config,
}

impl<'a> PolicyEngine<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    pub fn evaluate(
        &self,
        artifact: &Artifact,
        now: DateTime<Utc>,
        malicious_checker: &dyn MaliciousChecker,
    ) -> Decision {
        let allowlist_entry = self.find_allowlist_entry(artifact);

        if !allowlist_entry.is_some_and(|entry| entry.bypass_malicious) {
            match malicious_checker.check(artifact) {
                Ok(hits) => {
                    if let Some(hit) = self.blocking_malicious_hit(hits) {
                        return blocked(
                            DecisionReason::Malicious,
                            artifact,
                            format!("Blocked by OSV malicious package record {}", hit.osv_id),
                            Some(hit.osv_id),
                            Some(hit.source),
                            None,
                        );
                    }
                }
                Err(err) => {
                    if self.config.policy.malicious.on_osv_error == OsvErrorBehavior::Block {
                        return blocked(
                            DecisionReason::Malicious,
                            artifact,
                            format!("Blocked because OSV malicious check failed: {err}"),
                            None,
                            Some("osv".to_string()),
                            None,
                        );
                    }
                }
            }
        }

        if let Some(entry) = self.find_blocklist_entry(artifact) {
            return blocked(
                DecisionReason::ManuallyBlocked,
                artifact,
                "Blocked by manual package policy".to_string(),
                Some(format!("manual:blocklist:{}", entry.name)),
                Some("config".to_string()),
                None,
            );
        }

        if allowlist_entry.is_some_and(|entry| entry.bypass_age_gate) {
            return allowed(
                DecisionReason::Allowlisted,
                artifact,
                "Package version is allowlisted",
            );
        }

        let minimum_age = ChronoDuration::from_std(self.config.policy.minimum_age)
            .expect("minimum age duration should fit chrono duration");
        match artifact.published_at {
            Some(published_at) => {
                let eligible_at = published_at + minimum_age;
                if eligible_at > now {
                    return blocked(
                        DecisionReason::TooYoung,
                        artifact,
                        format!("Package version is too new; eligible at {eligible_at}"),
                        None,
                        Some("policy".to_string()),
                        Some(eligible_at),
                    );
                }
            }
            None => {
                if self.config.policy.missing_publish_time == MissingPublishTime::Block {
                    return blocked(
                        DecisionReason::MissingPublishTime,
                        artifact,
                        "Package version is missing publish time".to_string(),
                        None,
                        Some("policy".to_string()),
                        None,
                    );
                }
            }
        }

        if allowlist_entry.is_some() {
            allowed(
                DecisionReason::Allowlisted,
                artifact,
                "Package version is allowlisted",
            )
        } else {
            allowed(
                DecisionReason::Allowed,
                artifact,
                "Package version is allowed",
            )
        }
    }

    fn find_allowlist_entry(&self, artifact: &Artifact) -> Option<&'a AllowlistEntry> {
        self.config.allowlist.iter().find(|entry| {
            entry.ecosystem == artifact.ecosystem
                && entry.normalized_name() == artifact.name
                && entry.version == artifact.version
        })
    }

    fn find_blocklist_entry(
        &self,
        artifact: &Artifact,
    ) -> Option<&'a crate::config::BlocklistEntry> {
        self.config.blocklist.iter().find(|entry| {
            entry.ecosystem == artifact.ecosystem
                && entry.normalized_name() == artifact.name
                && (entry.versions.iter().any(|version| version == "*")
                    || entry
                        .versions
                        .iter()
                        .any(|version| version == &artifact.version))
        })
    }

    fn blocking_malicious_hit(&self, hits: Vec<MaliciousHit>) -> Option<MaliciousHit> {
        hits.into_iter().find(|hit| {
            !self.config.policy.malicious.only_mal_ids || hit.osv_id.starts_with("MAL-")
        })
    }
}

fn allowed(reason: DecisionReason, artifact: &Artifact, message: &str) -> Decision {
    Decision {
        allowed: true,
        reason,
        package: artifact.identity(),
        message: message.to_string(),
        rule_id: None,
        source: None,
        published_at: artifact.published_at,
        eligible_at: None,
    }
}

fn blocked(
    reason: DecisionReason,
    artifact: &Artifact,
    message: String,
    rule_id: Option<String>,
    source: Option<String>,
    eligible_at: Option<DateTime<Utc>>,
) -> Decision {
    Decision {
        allowed: false,
        reason,
        package: artifact.identity(),
        message,
        rule_id,
        source,
        published_at: artifact.published_at,
        eligible_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, Ecosystem};
    use crate::config::{
        AllowlistEntry, BlocklistEntry, MaliciousConfig, MaliciousMode, PolicyConfig,
    };
    use crate::malicious::MaliciousError;
    use std::cell::Cell;
    use std::time::Duration;

    struct FakeChecker {
        hits: Vec<MaliciousHit>,
        fail: bool,
        calls: Cell<u32>,
    }

    impl FakeChecker {
        fn clean() -> Self {
            Self {
                hits: Vec::new(),
                fail: false,
                calls: Cell::new(0),
            }
        }

        fn with_hit(osv_id: &str) -> Self {
            Self {
                hits: vec![MaliciousHit {
                    osv_id: osv_id.to_string(),
                    summary: None,
                    source: "osv".to_string(),
                    modified: None,
                }],
                fail: false,
                calls: Cell::new(0),
            }
        }

        fn failing() -> Self {
            Self {
                hits: Vec::new(),
                fail: true,
                calls: Cell::new(0),
            }
        }
    }

    impl MaliciousChecker for FakeChecker {
        fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                let err = reqwest::blocking::get("http://[::1").unwrap_err();
                return Err(MaliciousError::Request(err));
            }
            Ok(self.hits.clone())
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn old_artifact() -> Artifact {
        Artifact::package(
            Ecosystem::Npm,
            "lodash",
            "4.17.21",
            Some(now() - ChronoDuration::hours(100)),
        )
    }

    #[test]
    fn allows_old_package() {
        let config = Config::default();
        let decision =
            PolicyEngine::new(&config).evaluate(&old_artifact(), now(), &FakeChecker::clean());
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Allowed);
    }

    #[test]
    fn blocks_too_young_package() {
        let config = Config::default();
        let artifact = Artifact::package(
            Ecosystem::Npm,
            "lodash",
            "4.17.21",
            Some(now() - ChronoDuration::hours(12)),
        );
        let decision = PolicyEngine::new(&config).evaluate(&artifact, now(), &FakeChecker::clean());
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::TooYoung);
        assert!(decision.eligible_at.is_some());
    }

    #[test]
    fn blocks_missing_publish_time_by_default() {
        let config = Config::default();
        let artifact = Artifact::package(Ecosystem::Npm, "lodash", "4.17.21", None);
        let decision = PolicyEngine::new(&config).evaluate(&artifact, now(), &FakeChecker::clean());
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::MissingPublishTime);
    }

    #[test]
    fn can_allow_missing_publish_time() {
        let mut config = Config::default();
        config.policy.missing_publish_time = MissingPublishTime::Allow;
        let artifact = Artifact::package(Ecosystem::Npm, "lodash", "4.17.21", None);
        let decision = PolicyEngine::new(&config).evaluate(&artifact, now(), &FakeChecker::clean());
        assert!(decision.allowed);
    }

    #[test]
    fn blocks_manual_wildcard_blocklist() {
        let mut config = Config::default();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Npm,
            name: "lodash".to_string(),
            versions: vec!["*".to_string()],
            reason: "blocked".to_string(),
        });
        let decision =
            PolicyEngine::new(&config).evaluate(&old_artifact(), now(), &FakeChecker::clean());
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ManuallyBlocked);
    }

    #[test]
    fn blocks_manual_exact_blocklist() {
        let mut config = Config::default();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Npm,
            name: "lodash".to_string(),
            versions: vec!["4.17.21".to_string()],
            reason: "blocked".to_string(),
        });
        let decision =
            PolicyEngine::new(&config).evaluate(&old_artifact(), now(), &FakeChecker::clean());
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ManuallyBlocked);
    }

    #[test]
    fn mal_ids_block() {
        let config = Config::default();
        let decision = PolicyEngine::new(&config).evaluate(
            &old_artifact(),
            now(),
            &FakeChecker::with_hit("MAL-2026-000001"),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Malicious);
        assert_eq!(decision.rule_id.as_deref(), Some("MAL-2026-000001"));
    }

    #[test]
    fn non_mal_advisories_do_not_block_when_only_mal_ids_is_true() {
        let config = Config::default();
        let decision = PolicyEngine::new(&config).evaluate(
            &old_artifact(),
            now(),
            &FakeChecker::with_hit("GHSA-abcd-1234"),
        );
        assert!(decision.allowed);
    }

    #[test]
    fn non_mal_advisories_block_when_only_mal_ids_is_false() {
        let mut config = Config::default();
        config.policy.malicious.only_mal_ids = false;
        let decision = PolicyEngine::new(&config).evaluate(
            &old_artifact(),
            now(),
            &FakeChecker::with_hit("GHSA-abcd-1234"),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Malicious);
    }

    #[test]
    fn osv_error_blocks_by_default() {
        let config = Config::default();
        let decision =
            PolicyEngine::new(&config).evaluate(&old_artifact(), now(), &FakeChecker::failing());
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Malicious);
    }

    #[test]
    fn osv_error_can_allow() {
        let mut config = Config::default();
        config.policy.malicious.on_osv_error = OsvErrorBehavior::Allow;
        let decision =
            PolicyEngine::new(&config).evaluate(&old_artifact(), now(), &FakeChecker::failing());
        assert!(decision.allowed);
    }

    #[test]
    fn allowlist_bypass_malicious_skips_checker() {
        let mut config = Config::default();
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::Npm,
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            bypass_age_gate: true,
            bypass_malicious: true,
            reason: "false positive".to_string(),
        });
        let checker = FakeChecker::with_hit("MAL-2026-000001");
        let decision = PolicyEngine::new(&config).evaluate(&old_artifact(), now(), &checker);
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Allowlisted);
        assert_eq!(checker.calls.get(), 0);
    }

    #[test]
    fn allowlist_without_bypasses_still_checks_policy() {
        let mut config = Config {
            policy: PolicyConfig {
                minimum_age: Duration::from_secs(72 * 60 * 60),
                malicious: MaliciousConfig {
                    mode: MaliciousMode::Naive,
                    only_mal_ids: true,
                    osv_api_url: "https://api.osv.dev".to_string(),
                    on_osv_error: OsvErrorBehavior::Block,
                },
                ..PolicyConfig::default()
            },
            ..Config::default()
        };
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::Npm,
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            bypass_age_gate: false,
            bypass_malicious: false,
            reason: "tracked".to_string(),
        });
        let decision = PolicyEngine::new(&config).evaluate(
            &old_artifact(),
            now(),
            &FakeChecker::with_hit("MAL-2026-000001"),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Malicious);
    }
}
