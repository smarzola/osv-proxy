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

    pub async fn evaluate(
        &self,
        artifact: &Artifact,
        now: DateTime<Utc>,
        malicious_checker: &dyn MaliciousChecker,
    ) -> Decision {
        let malicious_result = if self.bypasses_malicious(artifact) {
            None
        } else {
            Some(
                malicious_checker
                    .check(artifact)
                    .await
                    .map_err(|err| err.to_string()),
            )
        };
        self.evaluate_with_malicious_result(artifact, now, malicious_result)
    }

    pub fn bypasses_malicious(&self, artifact: &Artifact) -> bool {
        self.find_allowlist_entry(artifact)
            .is_some_and(|entry| entry.bypass_malicious)
    }

    pub fn evaluate_with_malicious_result(
        &self,
        artifact: &Artifact,
        now: DateTime<Utc>,
        malicious_result: Option<Result<Vec<MaliciousHit>, String>>,
    ) -> Decision {
        let allowlist_entry = self.find_allowlist_entry(artifact);

        if !self.bypasses_malicious(artifact) {
            match malicious_result {
                Some(Ok(hits)) => {
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
                Some(Err(err)) => {
                    if self.config.policy.osv.on_error == OsvErrorBehavior::Block {
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
                None => {
                    if self.config.policy.osv.on_error == OsvErrorBehavior::Block {
                        return blocked(
                            DecisionReason::Malicious,
                            artifact,
                            "Blocked because OSV malicious check result was missing".to_string(),
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
        hits.into_iter().find(|hit| hit.osv_id.starts_with("MAL-"))
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
    use crate::config::{AllowlistEntry, BlocklistEntry, OsvConfig, PolicyConfig};
    use crate::malicious::MaliciousError;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    struct FakeChecker {
        hits: Vec<MaliciousHit>,
        fail: bool,
        calls: AtomicU32,
    }

    impl FakeChecker {
        fn clean() -> Self {
            Self {
                hits: Vec::new(),
                fail: false,
                calls: AtomicU32::new(0),
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
                calls: AtomicU32::new(0),
            }
        }

        fn failing() -> Self {
            Self {
                hits: Vec::new(),
                fail: true,
                calls: AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl MaliciousChecker for FakeChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(MaliciousError::InvalidBatchResponse {
                    expected: 1,
                    actual: 0,
                });
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

    #[tokio::test]
    async fn allows_old_package() {
        let config = Config::default();
        let decision = PolicyEngine::new(&config)
            .evaluate(&old_artifact(), now(), &FakeChecker::clean())
            .await;
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Allowed);
    }

    #[tokio::test]
    async fn blocks_too_young_package() {
        let config = Config::default();
        let artifact = Artifact::package(
            Ecosystem::Npm,
            "lodash",
            "4.17.21",
            Some(now() - ChronoDuration::hours(12)),
        );
        let decision = PolicyEngine::new(&config)
            .evaluate(&artifact, now(), &FakeChecker::clean())
            .await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::TooYoung);
        assert!(decision.eligible_at.is_some());
    }

    #[tokio::test]
    async fn blocks_missing_publish_time_by_default() {
        let config = Config::default();
        let artifact = Artifact::package(Ecosystem::Npm, "lodash", "4.17.21", None);
        let decision = PolicyEngine::new(&config)
            .evaluate(&artifact, now(), &FakeChecker::clean())
            .await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::MissingPublishTime);
    }

    #[tokio::test]
    async fn can_allow_missing_publish_time() {
        let mut config = Config::default();
        config.policy.missing_publish_time = MissingPublishTime::Allow;
        let artifact = Artifact::package(Ecosystem::Npm, "lodash", "4.17.21", None);
        let decision = PolicyEngine::new(&config)
            .evaluate(&artifact, now(), &FakeChecker::clean())
            .await;
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn blocks_manual_wildcard_blocklist() {
        let mut config = Config::default();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Npm,
            name: "lodash".to_string(),
            versions: vec!["*".to_string()],
            reason: "blocked".to_string(),
        });
        let decision = PolicyEngine::new(&config)
            .evaluate(&old_artifact(), now(), &FakeChecker::clean())
            .await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ManuallyBlocked);
    }

    #[tokio::test]
    async fn blocks_manual_exact_blocklist() {
        let mut config = Config::default();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Npm,
            name: "lodash".to_string(),
            versions: vec!["4.17.21".to_string()],
            reason: "blocked".to_string(),
        });
        let decision = PolicyEngine::new(&config)
            .evaluate(&old_artifact(), now(), &FakeChecker::clean())
            .await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::ManuallyBlocked);
    }

    #[tokio::test]
    async fn mal_ids_block() {
        let config = Config::default();
        let decision = PolicyEngine::new(&config)
            .evaluate(
                &old_artifact(),
                now(),
                &FakeChecker::with_hit("MAL-2026-000001"),
            )
            .await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Malicious);
        assert_eq!(decision.rule_id.as_deref(), Some("MAL-2026-000001"));
    }

    #[tokio::test]
    async fn non_mal_advisories_do_not_block() {
        let config = Config::default();
        let decision = PolicyEngine::new(&config)
            .evaluate(
                &old_artifact(),
                now(),
                &FakeChecker::with_hit("GHSA-abcd-1234"),
            )
            .await;
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn osv_error_blocks_by_default() {
        let config = Config::default();
        let decision = PolicyEngine::new(&config)
            .evaluate(&old_artifact(), now(), &FakeChecker::failing())
            .await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Malicious);
    }

    #[test]
    fn missing_malicious_result_blocks_non_bypassed_artifact_by_default() {
        let config = Config::default();
        let decision =
            PolicyEngine::new(&config).evaluate_with_malicious_result(&old_artifact(), now(), None);

        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Malicious);
        assert!(decision
            .message
            .contains("malicious check result was missing"));
    }

    #[tokio::test]
    async fn osv_error_can_allow() {
        let mut config = Config::default();
        config.policy.osv.on_error = OsvErrorBehavior::Allow;
        let decision = PolicyEngine::new(&config)
            .evaluate(&old_artifact(), now(), &FakeChecker::failing())
            .await;
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn allowlist_bypass_malicious_skips_checker() {
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
        let decision = PolicyEngine::new(&config)
            .evaluate(&old_artifact(), now(), &checker)
            .await;
        assert!(decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Allowlisted);
        assert_eq!(checker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn allowlist_without_bypasses_still_checks_policy() {
        let mut config = Config {
            policy: PolicyConfig {
                minimum_age: Duration::from_secs(72 * 60 * 60),
                osv: OsvConfig {
                    api_url: "https://api.osv.dev".to_string(),
                    on_error: OsvErrorBehavior::Block,
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
        let decision = PolicyEngine::new(&config)
            .evaluate(
                &old_artifact(),
                now(),
                &FakeChecker::with_hit("MAL-2026-000001"),
            )
            .await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Malicious);
    }
}
