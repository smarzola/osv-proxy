use crate::config::Config;
use crate::malicious::{OsvEcosystemReadiness, SqliteMaliciousChecker};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadinessReport {
    pub ready: bool,
    pub osv_source: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ecosystems: Vec<OsvEcosystemReadiness>,
}

pub async fn evaluate(config: &Config) -> ReadinessReport {
    let ecosystems = SqliteMaliciousChecker::with_vulnerability_policy(
        &config.policy.osv.local,
        config.policy.osv.block_vulnerabilities,
    )
    .readiness()
    .await;
    ReadinessReport {
        ready: ecosystems.iter().all(|ecosystem| ecosystem.ready),
        osv_source: "local",
        ecosystems,
    }
}
