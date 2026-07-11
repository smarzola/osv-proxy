use crate::artifact::Artifact;
use crate::config::{AllowlistEntry, Config, MissingPublishTime, OsvErrorBehavior};
use crate::malicious::{MaliciousChecker, MaliciousHit};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
        let malicious_result = if self.should_check_osv(artifact) {
            Some(
                malicious_checker
                    .check(artifact)
                    .await
                    .map_err(|err| err.to_string()),
            )
        } else {
            None
        };
        self.evaluate_with_malicious_result(artifact, now, malicious_result)
    }

    pub fn should_check_osv(&self, artifact: &Artifact) -> bool {
        (self.config.policy.osv.block_malicious || self.config.policy.osv.block_vulnerabilities)
            && !self
                .find_allowlist_entry(artifact)
                .is_some_and(|entry| entry.bypass_osv)
    }

    pub fn evaluate_with_malicious_result(
        &self,
        artifact: &Artifact,
        now: DateTime<Utc>,
        malicious_result: Option<Result<Vec<MaliciousHit>, String>>,
    ) -> Decision {
        let allowlist_entry = self.find_allowlist_entry(artifact);

        if self.should_check_osv(artifact) {
            match malicious_result {
                Some(Ok(hits)) => {
                    if let Some(hit) = self.blocking_malicious_hit(&hits) {
                        return blocked(
                            DecisionReason::Malicious,
                            artifact,
                            format!("Blocked by OSV malicious package record {}", hit.osv_id),
                            Some(hit.osv_id.clone()),
                            Some(hit.source.clone()),
                            None,
                        );
                    }
                    if let Some(hit) = self.blocking_vulnerability_hit(&hits) {
                        let score = hit
                            .effective_severity
                            .as_ref()
                            .map(|severity| severity.base_score);
                        let score_message = score
                            .map(|score| format!(" with CVSS base score {score:.1}"))
                            .unwrap_or_default();
                        let mut decision = blocked(
                            DecisionReason::Vulnerable,
                            artifact,
                            format!("Blocked by OSV vulnerability {}{score_message}", hit.osv_id),
                            Some(hit.osv_id.clone()),
                            Some(hit.source.clone()),
                            None,
                        );
                        decision.cvss_score = score;
                        return decision;
                    }
                    if let Some(hit) = hits
                        .iter()
                        .filter(|hit| hit.evaluation_error.is_some())
                        .min_by(|left, right| left.osv_id.cmp(&right.osv_id))
                        && self.config.policy.osv.on_error == OsvErrorBehavior::Block
                    {
                        let (message, rule_id) = if hit.osv_id.is_empty() {
                            (
                                format!(
                                    "Blocked because OSV query could not be evaluated: {}",
                                    hit.evaluation_error.as_deref().unwrap_or("unknown error")
                                ),
                                None,
                            )
                        } else {
                            (
                                format!(
                                    "Blocked because OSV advisory {} could not be evaluated: {}",
                                    hit.osv_id,
                                    hit.evaluation_error.as_deref().unwrap_or("unknown error")
                                ),
                                Some(hit.osv_id.clone()),
                            )
                        };
                        return blocked(
                            DecisionReason::Vulnerable,
                            artifact,
                            message,
                            rule_id,
                            Some(hit.source.clone()),
                            None,
                        );
                    }
                }
                Some(Err(err)) => {
                    if self.config.policy.osv.on_error == OsvErrorBehavior::Block {
                        let reason = self.osv_error_reason();
                        return blocked(
                            reason,
                            artifact,
                            format!("Blocked because OSV check failed: {err}"),
                            None,
                            Some("osv".to_string()),
                            None,
                        );
                    }
                }
                None => {
                    if self.config.policy.osv.on_error == OsvErrorBehavior::Block {
                        let reason = self.osv_error_reason();
                        return blocked(
                            reason,
                            artifact,
                            "Blocked because OSV check result was missing".to_string(),
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

    fn blocking_malicious_hit<'b>(&self, hits: &'b [MaliciousHit]) -> Option<&'b MaliciousHit> {
        self.config.policy.osv.block_malicious.then(|| {
            hits.iter()
                .filter(|hit| hit.osv_id.starts_with("MAL-"))
                .min_by(|left, right| left.osv_id.cmp(&right.osv_id))
        })?
    }

    fn blocking_vulnerability_hit<'b>(&self, hits: &'b [MaliciousHit]) -> Option<&'b MaliciousHit> {
        if !self.config.policy.osv.block_vulnerabilities {
            return None;
        }
        let threshold = self.config.policy.osv.minimum_cvss_score;
        hits.iter()
            .filter(|hit| !hit.osv_id.starts_with("MAL-"))
            .filter(|hit| hit.evaluation_error.is_none())
            .filter(|hit| {
                threshold == 0.0
                    || hit
                        .effective_severity
                        .as_ref()
                        .is_some_and(|severity| severity.base_score >= threshold)
            })
            .min_by(|left, right| {
                let left_score = left
                    .effective_severity
                    .as_ref()
                    .map(|value| value.base_score);
                let right_score = right
                    .effective_severity
                    .as_ref()
                    .map(|value| value.base_score);
                right_score
                    .partial_cmp(&left_score)
                    .unwrap_or(Ordering::Equal)
                    .then_with(|| left.osv_id.cmp(&right.osv_id))
            })
    }

    fn osv_error_reason(&self) -> DecisionReason {
        if self.config.policy.osv.block_malicious {
            DecisionReason::Malicious
        } else {
            DecisionReason::Vulnerable
        }
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
        cvss_score: None,
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
        cvss_score: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, Ecosystem};
    use crate::config::{AllowlistEntry, BlocklistEntry, OsvConfig, PolicyConfig};
    use crate::malicious::MaliciousError;
    use crate::malicious::OsvEffectiveSeverity;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    #[test]
    fn vulnerable_reason_serializes_without_changing_existing_names() {
        assert_eq!(
            serde_json::to_string(&DecisionReason::Vulnerable).unwrap(),
            r#""vulnerable""#
        );
        assert_eq!(
            serde_json::to_string(&DecisionReason::Malicious).unwrap(),
            r#""malicious""#
        );
        assert_eq!(
            serde_json::to_string(&DecisionReason::TooYoung).unwrap(),
            r#""too_young""#
        );
    }

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
                    effective_severity: None,
                    evaluation_error: None,
                }],
                fail: false,
                calls: AtomicU32::new(0),
            }
        }

        fn with_scored_hit(osv_id: &str, score: f64) -> Self {
            let mut checker = Self::with_hit(osv_id);
            checker.hits[0].effective_severity = Some(OsvEffectiveSeverity {
                severity_type: "CVSS_V3".to_string(),
                vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                base_score: score,
            });
            checker
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
    async fn unscored_vulnerability_blocks_at_default_zero_threshold() {
        let config = Config::default();
        let decision = PolicyEngine::new(&config)
            .evaluate(
                &old_artifact(),
                now(),
                &FakeChecker::with_hit("GHSA-abcd-1234"),
            )
            .await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, DecisionReason::Vulnerable);
        assert_eq!(decision.rule_id.as_deref(), Some("GHSA-abcd-1234"));
        assert_eq!(decision.cvss_score, None);
    }

    #[tokio::test]
    async fn positive_threshold_blocks_on_equality_and_reports_score() {
        let mut config = Config::default();
        config.policy.osv.minimum_cvss_score = 7.5;
        let decision = PolicyEngine::new(&config)
            .evaluate(
                &old_artifact(),
                now(),
                &FakeChecker::with_scored_hit("GHSA-abcd-1234", 7.5),
            )
            .await;
        assert_eq!(decision.reason, DecisionReason::Vulnerable);
        assert_eq!(decision.cvss_score, Some(7.5));

        config.policy.osv.minimum_cvss_score = 7.6;
        let decision = PolicyEngine::new(&config)
            .evaluate(
                &old_artifact(),
                now(),
                &FakeChecker::with_scored_hit("GHSA-abcd-1234", 7.5),
            )
            .await;
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn default_zero_threshold_reports_available_score() {
        let config = Config::default();
        let decision = PolicyEngine::new(&config)
            .evaluate(
                &old_artifact(),
                now(),
                &FakeChecker::with_scored_hit("GHSA-scored", 9.8),
            )
            .await;
        assert_eq!(decision.reason, DecisionReason::Vulnerable);
        assert_eq!(decision.cvss_score, Some(9.8));
    }

    #[test]
    fn malicious_precedes_vulnerabilities_and_vulnerability_order_is_deterministic() {
        let config = Config::default();
        let scored = |id: &str, score: f64| MaliciousHit {
            osv_id: id.to_string(),
            summary: None,
            source: "osv".to_string(),
            modified: None,
            effective_severity: Some(OsvEffectiveSeverity {
                severity_type: "CVSS_V3".to_string(),
                vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                base_score: score,
            }),
            evaluation_error: None,
        };
        let engine = PolicyEngine::new(&config);
        let first = engine.evaluate_with_malicious_result(
            &old_artifact(),
            now(),
            Some(Ok(vec![scored("GHSA-z", 8.0), scored("GHSA-a", 8.0)])),
        );
        assert_eq!(first.rule_id.as_deref(), Some("GHSA-a"));

        let mut malicious = scored("MAL-2026-1", 0.0);
        malicious.effective_severity = None;
        let decision = engine.evaluate_with_malicious_result(
            &old_artifact(),
            now(),
            Some(Ok(vec![scored("GHSA-z", 10.0), malicious])),
        );
        assert_eq!(decision.reason, DecisionReason::Malicious);
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
        assert!(decision.message.contains("OSV check result was missing"));
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
    async fn allowlist_bypass_osv_skips_checker() {
        let mut config = Config::default();
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::Npm,
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            bypass_age_gate: true,
            bypass_osv: true,
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
    async fn disabled_osv_malicious_blocking_skips_checker() {
        let mut config = Config::default();
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
        let checker = FakeChecker::with_hit("MAL-2026-000001");
        let decision = PolicyEngine::new(&config)
            .evaluate(&old_artifact(), now(), &checker)
            .await;

        assert!(decision.allowed);
        assert_eq!(checker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn allowlist_without_bypasses_still_checks_policy() {
        let mut config = Config {
            policy: PolicyConfig {
                minimum_age: Duration::from_secs(72 * 60 * 60),
                osv: OsvConfig {
                    block_malicious: true,
                    api_url: "https://api.osv.dev".to_string(),
                    on_error: OsvErrorBehavior::Block,
                    ..OsvConfig::default()
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
            bypass_osv: false,
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
