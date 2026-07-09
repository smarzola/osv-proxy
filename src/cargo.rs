use crate::artifact::{Artifact, ArtifactHashes, Ecosystem, normalize_cargo_name};
use crate::artifacts::{ArtifactDeliveryError, ArtifactDeliveryOptions, ArtifactDeliveryResponse};
use crate::config::Config;
use crate::malicious::MaliciousChecker;
use crate::policy::PolicyEngine;
use crate::response::RegistryResponse;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct CargoRegistryClient {
    sparse_index_url: String,
    client: Client,
}

impl CargoRegistryClient {
    pub fn new(config: &Config) -> Self {
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
        let url = format!("{}/{}", self.sparse_index_url, path);
        Ok(self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?)
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
    let mut retained = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let record = parse_record(line)?;
        let artifact = record_to_artifact(config, &name, record)?;
        if PolicyEngine::new(config)
            .evaluate(&artifact, now, checker)
            .await
            .allowed
        {
            retained.push(line);
        }
    }
    let body = if retained.is_empty() {
        Vec::new()
    } else {
        format!("{}\n", retained.join("\n")).into_bytes()
    };
    Ok(RegistryResponse {
        status: 200,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body,
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
        return Err(CargoError::Blocked(artifact.identity()));
    }
    delivery
        .client
        .deliver(
            config,
            artifact
                .upstream_url
                .clone()
                .expect("Cargo artifact has upstream URL"),
            delivery.request_headers,
        )
        .await
        .map_err(CargoError::Delivery)
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
        CargoError::Blocked(_) => 403,
        CargoError::VersionNotFound(_) => 404,
        CargoError::Request(_) | CargoError::Delivery(_) => 502,
        _ => 502,
    };
    RegistryResponse::json(
        status,
        &serde_json::json!({ "error": "cargo_registry_error", "message": error.to_string() }),
    )
    .expect("Cargo error should serialize")
}

#[derive(Debug, Error)]
pub enum CargoError {
    #[error("Cargo sparse-index request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("invalid Cargo crate name: {0}")]
    InvalidCrateName(String),
    #[error("invalid Cargo sparse-index record: {0}")]
    InvalidIndex(String),
    #[error("Cargo crate version not found: {0}")]
    VersionNotFound(String),
    #[error("Cargo artifact blocked by current policy: {0}")]
    Blocked(String),
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
        let response = index_response(
            &Config::default(),
            &upstream,
            &CleanChecker,
            "demo",
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            format!("{old_line}\n")
        );
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
}
