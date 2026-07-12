use crate::artifact::{Artifact, ArtifactHashes, Ecosystem, normalize_cargo_name};
use crate::artifacts::{ArtifactDeliveryError, ArtifactDeliveryOptions, ArtifactDeliveryResponse};
use crate::config::Config;
use crate::http_body::{self, HttpBodyError};
use crate::malicious::MaliciousChecker;
use crate::policy::{Decision, PolicyEngine};
use crate::response::RegistryResponse;
use crate::runtime::{BudgetError, RuntimeBudgets};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CARGO_INDEX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CargoRegistryClient {
    sparse_index_url: String,
    client: Client,
    budgets: Arc<RuntimeBudgets>,
}

impl CargoRegistryClient {
    pub fn new(config: &Config) -> Self {
        Self::with_budgets(config, Arc::new(RuntimeBudgets::new(&config.limits)))
    }

    pub fn with_budgets(config: &Config, budgets: Arc<RuntimeBudgets>) -> Self {
        Self {
            sparse_index_url: config
                .upstreams
                .cargo
                .sparse_index_url
                .trim_end_matches('/')
                .to_string(),
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("Cargo HTTP client should build with static timeout configuration"),
            budgets,
        }
    }
}

#[async_trait]
pub trait CargoIndexProvider: Send + Sync {
    async fn fetch_index(&self, path: &str) -> Result<String, CargoError>;
}

#[async_trait]
impl CargoIndexProvider for CargoRegistryClient {
    async fn fetch_index(&self, path: &str) -> Result<String, CargoError> {
        let _permit = self.budgets.install_egress().await?;
        let url = format!("{}/{}", self.sparse_index_url, path);
        let response = self.client.get(url).send().await?.error_for_status()?;
        Ok(
            http_body::collect_text(response, MAX_CARGO_INDEX_BYTES, "Cargo sparse index entry")
                .await?,
        )
    }
}

#[derive(Debug, Deserialize)]
struct IndexRecord {
    name: String,
    vers: String,
    cksum: String,
    #[serde(default)]
    pubtime: Option<String>,
}

pub fn sparse_path(name: &str) -> Result<String, CargoError> {
    let name = normalize_cargo_name(name);
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(CargoError::InvalidCrateName(name));
    }
    let chars = name.as_bytes();
    Ok(match chars.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", chars[0] as char),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    })
}

pub fn name_from_sparse_path(path: &str) -> Result<String, CargoError> {
    let name = path.rsplit('/').next().unwrap_or_default();
    let name = normalize_cargo_name(name);
    if sparse_path(&name)? != path {
        return Err(CargoError::InvalidCrateName(path.to_string()));
    }
    Ok(name)
}

pub fn config_response(config: &Config) -> RegistryResponse {
    let download = format!(
        "{}/cargo/api/v1/crates",
        config.server.public_base_url.trim_end_matches('/')
    );
    RegistryResponse::json(200, &serde_json::json!({ "dl": download }))
        .expect("static Cargo config should serialize")
}

pub async fn lookup_artifact(
    config: &Config,
    provider: &dyn CargoIndexProvider,
    name: &str,
    version: &str,
) -> Result<Artifact, CargoError> {
    let name = normalize_cargo_name(name);
    let raw = provider.fetch_index(&sparse_path(&name)?).await?;
    let record = parse_records(&raw)?
        .into_iter()
        .find(|record| record.vers == version)
        .ok_or_else(|| CargoError::VersionNotFound(format!("{name}@{version}")))?;
    record_to_artifact(config, &name, record)
}

pub async fn index_response(
    config: &Config,
    provider: &dyn CargoIndexProvider,
    checker: &dyn MaliciousChecker,
    name: &str,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, CargoError> {
    let name = normalize_cargo_name(name);
    let raw = provider.fetch_index(&sparse_path(&name)?).await?;
    let mut lines = Vec::new();
    let mut artifacts = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let record = parse_record(line)?;
        lines.push(line);
        artifacts.push(record_to_artifact(config, &name, record)?);
    }
    let decisions = evaluate_artifacts(config, checker, &artifacts, now).await;
    let retained = lines
        .into_iter()
        .zip(decisions)
        .filter_map(|(line, decision)| decision.allowed.then_some(line))
        .collect::<Vec<_>>();
    let body = if retained.is_empty() {
        Vec::new()
    } else {
        format!("{}\n", retained.join("\n")).into_bytes()
    };
    let etag = format!("\"{:016x}\"", stable_hash(&body));
    Ok(RegistryResponse {
        status: 200,
        headers: vec![
            ("content-type".to_string(), "text/plain".to_string()),
            ("etag".to_string(), etag),
        ],
        body,
    })
}

pub fn apply_if_none_match(
    mut response: RegistryResponse,
    if_none_match: Option<&str>,
) -> RegistryResponse {
    let etag = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("etag"))
        .map(|(_, value)| value.as_str());
    if if_none_match.is_some_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == "*" || Some(candidate) == etag)
    }) {
        response.status = 304;
        response.body.clear();
    }
    response
}

fn stable_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

pub async fn artifact_delivery_response(
    config: &Config,
    provider: &dyn CargoIndexProvider,
    checker: &dyn MaliciousChecker,
    name: &str,
    version: &str,
    now: DateTime<Utc>,
    delivery: ArtifactDeliveryOptions<'_>,
) -> Result<ArtifactDeliveryResponse, CargoError> {
    let artifact = lookup_artifact(config, provider, name, version).await?;
    let decision = PolicyEngine::new(config)
        .evaluate(&artifact, now, checker)
        .await;
    if !decision.allowed {
        return Err(CargoError::Denied(Box::new(decision)));
    }
    delivery
        .client
        .deliver(
            config,
            artifact.ecosystem,
            artifact
                .upstream_url
                .clone()
                .expect("Cargo artifact has upstream URL"),
            delivery.request_headers,
        )
        .await
        .map_err(CargoError::Delivery)
}

pub async fn artifact_response(
    config: &Config,
    provider: &dyn CargoIndexProvider,
    checker: &dyn MaliciousChecker,
    name: &str,
    version: &str,
    now: DateTime<Utc>,
) -> RegistryResponse {
    let delivery = crate::artifacts::ArtifactDeliveryClient::for_config(config);
    match artifact_delivery_response(
        config,
        provider,
        checker,
        name,
        version,
        now,
        ArtifactDeliveryOptions::new(&delivery),
    )
    .await
    {
        Ok(response) => response.into_registry_response().await,
        Err(error) => error_response(&error),
    }
}

async fn evaluate_artifacts(
    config: &Config,
    checker: &dyn MaliciousChecker,
    artifacts: &[Artifact],
    now: DateTime<Utc>,
) -> Vec<Decision> {
    let policy = PolicyEngine::new(config);
    let indexed = artifacts
        .iter()
        .enumerate()
        .filter(|(_, artifact)| policy.should_check_osv(artifact))
        .map(|(index, artifact)| (index, artifact.clone()))
        .collect::<Vec<_>>();
    let checked = indexed
        .iter()
        .map(|(_, artifact)| artifact.clone())
        .collect::<Vec<_>>();
    let results = if checked.is_empty() {
        Ok(Vec::new())
    } else {
        match checker.check_many(&checked).await {
            Ok(results) if results.len() == checked.len() => Ok(results),
            Ok(results) => Err(format!(
                "malicious batch returned {} results for {} artifacts",
                results.len(),
                checked.len()
            )),
            Err(error) => Err(error.to_string()),
        }
    };
    artifacts
        .iter()
        .enumerate()
        .map(|(index, artifact)| {
            let result = indexed
                .iter()
                .position(|(artifact_index, _)| *artifact_index == index)
                .map(|batch_index| match &results {
                    Ok(results) => results.get(batch_index).cloned().ok_or_else(|| {
                        format!("malicious batch result missing for {}", artifact.identity())
                    }),
                    Err(error) => Err(error.clone()),
                });
            policy.evaluate_with_malicious_result(artifact, now, result)
        })
        .collect()
}

fn parse_records(raw: &str) -> Result<Vec<IndexRecord>, CargoError> {
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_record)
        .collect()
}

fn parse_record(line: &str) -> Result<IndexRecord, CargoError> {
    serde_json::from_str(line).map_err(|error| CargoError::InvalidIndex(error.to_string()))
}

fn record_to_artifact(
    config: &Config,
    expected_name: &str,
    record: IndexRecord,
) -> Result<Artifact, CargoError> {
    if normalize_cargo_name(&record.name) != expected_name {
        return Err(CargoError::InvalidIndex(format!(
            "record name {} does not match requested crate {expected_name}",
            record.name
        )));
    }
    let published_at = match record.pubtime {
        Some(value) => Some(
            DateTime::parse_from_rfc3339(&value)
                .map_err(|error| {
                    CargoError::InvalidIndex(format!("invalid pubtime {value}: {error}"))
                })?
                .with_timezone(&Utc),
        ),
        None => None,
    };
    let mut artifact = Artifact::package(
        Ecosystem::CratesIo,
        expected_name,
        record.vers.clone(),
        published_at,
    );
    artifact.filename = Some(format!("{}-{}.crate", expected_name, record.vers));
    artifact.upstream_url = Some(format!(
        "{}/{}/{}-{}.crate",
        config.upstreams.cargo.download_url.trim_end_matches('/'),
        expected_name,
        expected_name,
        record.vers
    ));
    artifact.hashes = ArtifactHashes {
        sha256: Some(record.cksum),
        ..ArtifactHashes::default()
    };
    Ok(artifact)
}

pub fn error_response(error: &CargoError) -> RegistryResponse {
    let status = match error {
        CargoError::Denied(_) => 403,
        CargoError::VersionNotFound(_) => 404,
        CargoError::Request(_) | CargoError::Delivery(_) => 502,
        _ => 502,
    };
    if let CargoError::Denied(decision) = error {
        return RegistryResponse::json(
            403,
            &serde_json::to_value(decision).expect("decision should serialize"),
        )
        .expect("Cargo denial should serialize");
    }
    RegistryResponse::json(
        status,
        &serde_json::json!({ "error": "cargo_registry_error", "message": error.to_string() }),
    )
    .expect("Cargo error should serialize")
}

#[derive(Debug, Error)]
pub enum CargoError {
    #[error("Cargo upstream concurrency limit failed: {0}")]
    Budget(#[from] BudgetError),
    #[error("Cargo sparse-index request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Cargo upstream body failed validation: {0}")]
    Body(#[from] HttpBodyError),
    #[error("invalid Cargo crate name: {0}")]
    InvalidCrateName(String),
    #[error("invalid Cargo sparse-index record: {0}")]
    InvalidIndex(String),
    #[error("Cargo crate version not found: {0}")]
    VersionNotFound(String),
    #[error("Cargo artifact blocked by current policy")]
    Denied(Box<Decision>),
    #[error("Cargo artifact delivery failed: {0}")]
    Delivery(ArtifactDeliveryError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::malicious::{MaliciousChecker, MaliciousError, MaliciousHit};
    use async_trait::async_trait;
    use chrono::Duration as ChronoDuration;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::time::{Duration as TokioDuration, timeout};

    struct StaticIndex(HashMap<String, String>);

    #[async_trait]
    impl CargoIndexProvider for StaticIndex {
        async fn fetch_index(&self, path: &str) -> Result<String, CargoError> {
            self.0
                .get(path)
                .cloned()
                .ok_or_else(|| CargoError::InvalidIndex("missing fixture".to_string()))
        }
    }

    struct CleanChecker;

    #[async_trait]
    impl MaliciousChecker for CleanChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            Ok(Vec::new())
        }
    }

    struct BatchChecker {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl MaliciousChecker for BatchChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            panic!("Cargo index filtering must use check_many")
        }
        async fn check_many(
            &self,
            artifacts: &[Artifact],
        ) -> Result<Vec<Vec<MaliciousHit>>, MaliciousError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![Vec::new(); artifacts.len()])
        }
    }
    #[test]
    fn maps_sparse_paths() {
        assert_eq!(sparse_path("a").unwrap(), "1/a");
        assert_eq!(sparse_path("ab").unwrap(), "2/ab");
        assert_eq!(sparse_path("abc").unwrap(), "3/a/abc");
        assert_eq!(sparse_path("Serde").unwrap(), "se/rd/serde");
    }

    #[tokio::test]
    async fn lookup_builds_canonical_crates_io_artifact() {
        let upstream = StaticIndex(HashMap::from([("de/mo/demo".to_string(), "{\"name\":\"demo\",\"vers\":\"1.0.0-beta.1\",\"cksum\":\"abc\",\"pubtime\":\"2024-01-01T00:00:00Z\"}\n".to_string())]));
        let artifact = lookup_artifact(&Config::default(), &upstream, "Demo", "1.0.0-beta.1")
            .await
            .unwrap();
        assert_eq!(artifact.identity(), "crates.io:demo@1.0.0-beta.1");
        assert_eq!(artifact.hashes.sha256.as_deref(), Some("abc"));
        assert_eq!(
            artifact.published_at.unwrap().to_rfc3339(),
            "2024-01-01T00:00:00+00:00"
        );
    }

    #[tokio::test]
    async fn index_filter_preserves_allowed_lines_and_excludes_too_new_versions() {
        let old = (Utc::now() - ChronoDuration::hours(100)).format("%Y-%m-%dT%H:%M:%SZ");
        let new = (Utc::now() - ChronoDuration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ");
        let old_line = format!(
            "{{\"name\":\"demo\",\"vers\":\"1.0.0\",\"deps\":[],\"cksum\":\"old\",\"yanked\":false,\"pubtime\":\"{old}\",\"x-forward\":true}}"
        );
        let new_line = format!(
            "{{\"name\":\"demo\",\"vers\":\"2.0.0\",\"deps\":[],\"cksum\":\"new\",\"yanked\":true,\"pubtime\":\"{new}\"}}"
        );
        let upstream = StaticIndex(HashMap::from([(
            "de/mo/demo".to_string(),
            format!("{old_line}\n{new_line}\n"),
        )]));
        let checker = BatchChecker {
            calls: AtomicUsize::new(0),
        };
        let response = index_response(&Config::default(), &upstream, &checker, "demo", Utc::now())
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            format!("{old_line}\n")
        );
        assert_eq!(checker.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn malformed_index_records_fail_closed() {
        let upstream = StaticIndex(HashMap::from([(
            "de/mo/demo".to_string(),
            "not json\n".to_string(),
        )]));
        let error = index_response(
            &Config::default(),
            &upstream,
            &CleanChecker,
            "demo",
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid Cargo sparse-index record")
        );
    }

    #[test]
    fn conditional_index_response_returns_304_for_its_etag() {
        let response = RegistryResponse {
            status: 200,
            headers: vec![("etag".to_string(), "\"abc\"".to_string())],
            body: b"index".to_vec(),
        };
        let response = apply_if_none_match(response, Some("\"abc\""));
        assert_eq!(response.status, 304);
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn blocked_artifact_is_rechecked_before_delivery() {
        let upstream = StaticIndex(HashMap::from([("de/mo/demo".to_string(), "{\"name\":\"demo\",\"vers\":\"1.0.0\",\"cksum\":\"abc\",\"pubtime\":\"2024-01-01T00:00:00Z\"}\n".to_string())]));
        let mut config = Config::default();
        config.blocklist.push(crate::config::BlocklistEntry {
            ecosystem: Ecosystem::CratesIo,
            name: "demo".to_string(),
            versions: vec!["1.0.0".to_string()],
            reason: "fixture".to_string(),
        });
        config.artifacts.behavior = crate::config::ArtifactBehavior::Proxy;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.upstreams.cargo.download_url =
            format!("http://{}/not-contacted", listener.local_addr().unwrap());
        let response = artifact_response(
            &config,
            &upstream,
            &CleanChecker,
            "demo",
            "1.0.0",
            Utc::now(),
        )
        .await;
        assert_eq!(response.status, 403);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["allowed"], false);
        assert_eq!(body["reason"], "manually_blocked");
        assert_eq!(body["rule_id"], "manual:blocklist:demo");
        assert!(
            timeout(TokioDuration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }
}
