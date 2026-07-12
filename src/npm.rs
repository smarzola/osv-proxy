use crate::artifact::{Artifact, ArtifactHashes, Ecosystem};
use crate::artifacts::{
    self, ArtifactDeliveryClient, ArtifactDeliveryError, ArtifactDeliveryOptions,
    ArtifactDeliveryResponse,
};
use crate::config::Config;
use crate::http_body::{self, HttpBodyError};
use crate::malicious::MaliciousChecker;
use crate::policy::PolicyEngine;
use crate::response::RegistryResponse;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::{Map, Value, json};
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NPM_METADATA_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct NpmRegistryClient {
    registry_url: String,
    client: Client,
}

impl NpmRegistryClient {
    pub fn new(registry_url: impl Into<String>) -> Self {
        Self {
            registry_url: registry_url.into().trim_end_matches('/').to_string(),
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("npm HTTP client should build with static timeout configuration"),
        }
    }
}

#[async_trait]
pub trait NpmMetadataProvider: Send + Sync {
    async fn fetch_package_metadata(&self, package: &str) -> Result<Value, NpmError>;
}

#[async_trait]
impl NpmMetadataProvider for NpmRegistryClient {
    async fn fetch_package_metadata(&self, package: &str) -> Result<Value, NpmError> {
        let url = format!(
            "{}/{}",
            self.registry_url,
            encode_package_for_registry(package)
        );
        let response = self.client.get(url).send().await?.error_for_status()?;
        Ok(
            http_body::collect_json(response, MAX_NPM_METADATA_BYTES, "npm package metadata")
                .await?,
        )
    }
}

pub type NpmResponse = RegistryResponse;

pub fn package_artifact(
    name: impl AsRef<str>,
    version: impl Into<String>,
    published_at: Option<DateTime<Utc>>,
) -> Artifact {
    Artifact::package(Ecosystem::Npm, name, version, published_at)
}

pub async fn metadata_response(
    config: &Config,
    upstream: &dyn NpmMetadataProvider,
    checker: &dyn MaliciousChecker,
    package: &str,
    now: DateTime<Utc>,
) -> Result<NpmResponse, NpmError> {
    let raw = upstream.fetch_package_metadata(package).await?;
    let filtered = filter_metadata(config, checker, package, raw, now).await?;
    Ok(NpmResponse::json(200, &filtered)?)
}

pub async fn lookup_artifact(
    upstream: &dyn NpmMetadataProvider,
    package: &str,
    version: &str,
) -> Result<Artifact, NpmError> {
    let metadata = upstream.fetch_package_metadata(package).await?;
    artifact_from_package_metadata(package, version, &metadata)
}

pub async fn artifact_response(
    config: &Config,
    upstream: &dyn NpmMetadataProvider,
    checker: &dyn MaliciousChecker,
    package: &str,
    tarball: &str,
    now: DateTime<Utc>,
) -> Result<NpmResponse, NpmError> {
    let delivery = ArtifactDeliveryClient::for_config(config);
    let response = artifact_delivery_response(
        config,
        upstream,
        checker,
        NpmArtifactRoute { package, tarball },
        now,
        ArtifactDeliveryOptions::new(&delivery),
    )
    .await?;
    Ok(response.into_registry_response().await)
}

#[derive(Clone, Copy)]
pub struct NpmArtifactRoute<'a> {
    pub package: &'a str,
    pub tarball: &'a str,
}

pub async fn artifact_delivery_response(
    config: &Config,
    upstream: &dyn NpmMetadataProvider,
    checker: &dyn MaliciousChecker,
    route: NpmArtifactRoute<'_>,
    now: DateTime<Utc>,
    delivery: ArtifactDeliveryOptions<'_>,
) -> Result<ArtifactDeliveryResponse, NpmError> {
    let version = infer_version_from_tarball(route.package, route.tarball)
        .ok_or_else(|| NpmError::InvalidTarballName(route.tarball.to_string()))?;
    let metadata = upstream.fetch_package_metadata(route.package).await?;
    let artifact = artifact_from_metadata(route.package, &version, route.tarball, &metadata)?;
    let decision = PolicyEngine::new(config)
        .evaluate(&artifact, now, checker)
        .await;

    if decision.allowed {
        let location = artifact
            .upstream_url
            .ok_or_else(|| NpmError::MissingTarballUrl(route.package.to_string(), version))?;
        Ok(delivery
            .client
            .deliver(config, Ecosystem::Npm, location, delivery.request_headers)
            .await?)
    } else {
        let body = serde_json::to_value(decision)?;
        Ok(ArtifactDeliveryResponse::Buffered(NpmResponse::json(
            403, &body,
        )?))
    }
}

pub fn error_response(error: &NpmError) -> NpmResponse {
    if let NpmError::ArtifactDelivery(error) = error {
        return artifacts::gateway_error_response(error);
    }
    let status = match error {
        NpmError::VersionNotFound(_, _)
        | NpmError::MissingTarballUrl(_, _)
        | NpmError::InvalidTarballName(_)
        | NpmError::TarballBasenameMismatch { .. } => 404,
        NpmError::Upstream(_) | NpmError::Body(_) | NpmError::ArtifactDelivery(_) => 502,
        NpmError::Json(_) | NpmError::InvalidMetadata(_) => 500,
    };
    let body = json!({
        "allowed": false,
        "reason": "upstream_error",
        "message": error.to_string(),
    });
    NpmResponse::json(status, &body).expect("static error response should serialize")
}

async fn filter_metadata(
    config: &Config,
    checker: &dyn MaliciousChecker,
    package: &str,
    mut metadata: Value,
    now: DateTime<Utc>,
) -> Result<Value, NpmError> {
    let mut kept_versions = Vec::new();
    let time_metadata = metadata.get("time").cloned();
    let versions = metadata
        .get_mut("versions")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| NpmError::InvalidMetadata("metadata.versions must be an object".into()))?;
    let version_names = versions.keys().cloned().collect::<Vec<_>>();
    let artifacts = version_names
        .iter()
        .map(|version| {
            let version_metadata = versions
                .get(version)
                .expect("version key should exist while collecting npm artifacts");
            let published_at = time_metadata
                .as_ref()
                .and_then(|time| time.get(version))
                .and_then(Value::as_str)
                .and_then(parse_npm_time);
            artifact_from_version_metadata(package, version, version_metadata, published_at)
        })
        .collect::<Vec<_>>();
    let policy = PolicyEngine::new(config);
    let artifacts_to_check = artifacts
        .iter()
        .enumerate()
        .filter(|(_, artifact)| policy.should_check_osv(artifact))
        .map(|(index, artifact)| (index, artifact.clone()))
        .collect::<Vec<_>>();
    let checked_artifacts = artifacts_to_check
        .iter()
        .map(|(_, artifact)| artifact.clone())
        .collect::<Vec<_>>();
    let malicious_results = if checked_artifacts.is_empty() {
        Ok(Vec::new())
    } else {
        match checker
            .check_many(&checked_artifacts)
            .await
            .map_err(|err| err.to_string())
        {
            Ok(results) if results.len() == checked_artifacts.len() => Ok(results),
            Ok(results) => Err(format!(
                "malicious batch returned {} results for {} artifacts",
                results.len(),
                checked_artifacts.len()
            )),
            Err(err) => Err(err),
        }
    };

    for (index, version) in version_names.iter().enumerate() {
        let Some(version_metadata) = versions.get_mut(version) else {
            continue;
        };
        let published_at = time_metadata
            .as_ref()
            .and_then(|time| time.get(version))
            .and_then(Value::as_str)
            .and_then(parse_npm_time);
        let artifact =
            artifact_from_version_metadata(package, version, version_metadata, published_at);
        let malicious_result = if let Some(batch_index) = artifacts_to_check
            .iter()
            .position(|(artifact_index, _)| *artifact_index == index)
        {
            match &malicious_results {
                Ok(results) => results.get(batch_index).cloned().map(Ok).or_else(|| {
                    Some(Err(format!(
                        "malicious batch result missing for {}",
                        artifact.identity()
                    )))
                }),
                Err(err) => Some(Err(err.clone())),
            }
        } else {
            None
        };
        let decision = PolicyEngine::new(config).evaluate_with_malicious_result(
            &artifact,
            now,
            malicious_result,
        );
        if decision.allowed {
            if let Some(dist) = version_metadata
                .get_mut("dist")
                .and_then(Value::as_object_mut)
            {
                let tarball = dist
                    .get("tarball")
                    .and_then(Value::as_str)
                    .and_then(tarball_filename)
                    .unwrap_or_else(|| default_tarball_filename(package, version));
                dist.insert(
                    "tarball".to_string(),
                    Value::String(proxy_tarball_url(config, package, &tarball)),
                );
            }
            kept_versions.push(version.clone());
        } else {
            versions.remove(version);
        }
    }

    if let Some(dist_tags) = metadata.get_mut("dist-tags").and_then(Value::as_object_mut) {
        dist_tags.retain(|_, tagged_version| {
            tagged_version
                .as_str()
                .is_some_and(|version| kept_versions.iter().any(|kept| kept == version))
        });
    }

    Ok(metadata)
}

fn artifact_from_metadata(
    package: &str,
    version: &str,
    tarball: &str,
    metadata: &Value,
) -> Result<Artifact, NpmError> {
    let mut artifact = artifact_from_package_metadata(package, version, metadata)?;
    let expected_tarball = artifact
        .filename
        .clone()
        .ok_or_else(|| NpmError::MissingTarballUrl(package.to_string(), version.to_string()))?;
    if expected_tarball != tarball {
        return Err(NpmError::TarballBasenameMismatch {
            package: package.to_string(),
            version: version.to_string(),
            requested: tarball.to_string(),
            expected: expected_tarball,
        });
    }
    artifact.filename = Some(tarball.to_string());
    Ok(artifact)
}

fn artifact_from_package_metadata(
    package: &str,
    version: &str,
    metadata: &Value,
) -> Result<Artifact, NpmError> {
    let versions = metadata
        .get("versions")
        .and_then(Value::as_object)
        .ok_or_else(|| NpmError::InvalidMetadata("metadata.versions must be an object".into()))?;
    let version_metadata = versions
        .get(version)
        .ok_or_else(|| NpmError::VersionNotFound(package.to_string(), version.to_string()))?;
    let published_at = metadata
        .get("time")
        .and_then(|time| time.get(version))
        .and_then(Value::as_str)
        .and_then(parse_npm_time);
    let artifact = artifact_from_version_metadata(package, version, version_metadata, published_at);
    if artifact.upstream_url.is_none() || artifact.filename.is_none() {
        return Err(NpmError::MissingTarballUrl(
            package.to_string(),
            version.to_string(),
        ));
    }
    Ok(artifact)
}

fn artifact_from_version_metadata(
    package: &str,
    version: &str,
    version_metadata: &Value,
    published_at: Option<DateTime<Utc>>,
) -> Artifact {
    let mut artifact = package_artifact(package, version.to_string(), published_at);

    let dist = version_metadata.get("dist").and_then(Value::as_object);
    if let Some(dist) = dist {
        artifact.upstream_url = dist
            .get("tarball")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        artifact.filename = artifact.upstream_url.as_deref().and_then(tarball_filename);
        artifact.hashes = hashes_from_dist(dist);
    }

    artifact
}

fn hashes_from_dist(dist: &Map<String, Value>) -> ArtifactHashes {
    let integrity = dist
        .get("integrity")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let sha512 = integrity
        .as_deref()
        .and_then(|value| value.strip_prefix("sha512-"))
        .map(ToOwned::to_owned);

    ArtifactHashes {
        sha256: None,
        sha512,
        integrity,
    }
}

fn parse_npm_time(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn proxy_tarball_url(config: &Config, package: &str, tarball: &str) -> String {
    format!(
        "{}/npm/{}/-/{}",
        config.server.public_base_url.trim_end_matches('/'),
        package.trim_start_matches('/'),
        tarball
    )
}

fn tarball_filename(url: &str) -> Option<String> {
    let without_fragment = url.split('#').next().unwrap_or(url);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    without_query
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .map(ToOwned::to_owned)
}

fn default_tarball_filename(package: &str, version: &str) -> String {
    format!("{}-{version}.tgz", package_file_stem(package))
}

fn package_file_stem(package: &str) -> &str {
    package.rsplit('/').next().unwrap_or(package)
}

fn infer_version_from_tarball(package: &str, tarball: &str) -> Option<String> {
    let stem = tarball.strip_suffix(".tgz")?;
    let expected_prefix = format!("{}-", package_file_stem(package));
    if let Some(version) = stem.strip_prefix(&expected_prefix) {
        return (!version.is_empty()).then(|| version.to_string());
    }
    stem.rsplit_once('-')
        .and_then(|(_, version)| (!version.is_empty()).then(|| version.to_string()))
}

fn encode_package_for_registry(package: &str) -> String {
    if package.starts_with('@') {
        package.replacen('/', "%2F", 1)
    } else {
        package.to_string()
    }
}

#[derive(Debug, Error)]
pub enum NpmError {
    #[error("npm upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("npm upstream body failed validation: {0}")]
    Body(#[from] HttpBodyError),
    #[error("npm JSON handling failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid npm metadata: {0}")]
    InvalidMetadata(String),
    #[error("npm version not found for {0}@{1}")]
    VersionNotFound(String, String),
    #[error("npm tarball URL missing for {0}@{1}")]
    MissingTarballUrl(String, String),
    #[error("could not infer npm version from tarball name {0}")]
    InvalidTarballName(String),
    #[error(
        "requested npm tarball {requested} does not match upstream basename {expected} for {package}@{version}"
    )]
    TarballBasenameMismatch {
        package: String,
        version: String,
        requested: String,
        expected: String,
    },
    #[error("npm artifact delivery failed: {0}")]
    ArtifactDelivery(#[from] ArtifactDeliveryError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::Ecosystem;
    use crate::config::{AllowlistEntry, ArtifactBehavior, BlocklistEntry};
    use crate::malicious::{MaliciousError, MaliciousHit};
    use crate::policy::Decision;
    use async_trait::async_trait;
    use axum::http::{HeaderMap, header};
    use chrono::Duration as ChronoDuration;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    struct StaticUpstream {
        metadata: HashMap<String, Value>,
    }

    impl StaticUpstream {
        fn new(package: &str, metadata: Value) -> Self {
            Self {
                metadata: HashMap::from([(package.to_string(), metadata)]),
            }
        }
    }

    #[async_trait]
    impl NpmMetadataProvider for StaticUpstream {
        async fn fetch_package_metadata(&self, package: &str) -> Result<Value, NpmError> {
            self.metadata.get(package).cloned().ok_or_else(|| {
                NpmError::InvalidMetadata(format!("missing static metadata for {package}"))
            })
        }
    }

    struct CleanChecker {
        calls: AtomicU32,
        batch_calls: AtomicU32,
        batch_artifacts: Mutex<Vec<String>>,
    }

    impl CleanChecker {
        fn new() -> Self {
            Self {
                calls: AtomicU32::new(0),
                batch_calls: AtomicU32::new(0),
                batch_artifacts: Mutex::new(Vec::new()),
            }
        }

        fn batch_identities(&self) -> Vec<String> {
            self.batch_artifacts.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MaliciousChecker for CleanChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }

        async fn check_many(
            &self,
            artifacts: &[Artifact],
        ) -> Result<Vec<Vec<MaliciousHit>>, MaliciousError> {
            self.batch_calls.fetch_add(1, Ordering::SeqCst);
            self.batch_artifacts
                .lock()
                .unwrap()
                .extend(artifacts.iter().map(Artifact::identity));
            Ok(vec![Vec::new(); artifacts.len()])
        }
    }

    struct ShortBatchChecker;

    #[async_trait]
    impl MaliciousChecker for ShortBatchChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            Ok(Vec::new())
        }

        async fn check_many(
            &self,
            artifacts: &[Artifact],
        ) -> Result<Vec<Vec<MaliciousHit>>, MaliciousError> {
            Ok(vec![Vec::new(); artifacts.len().saturating_sub(1)])
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn metadata_fixture() -> Value {
        json!({
            "name": "demo",
            "dist-tags": {
                "latest": "2.0.0",
                "blocked": "1.0.1",
                "stable": "1.0.0"
            },
            "time": {
                "1.0.0": "2026-06-01T00:00:00Z",
                "1.0.1": "2026-06-01T00:00:00Z",
                "2.0.0": "2026-07-05T00:00:00Z"
            },
            "versions": {
                "1.0.0": {
                    "name": "demo",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.example/demo/-/demo-1.0.0.tgz",
                        "integrity": "sha512-allowed",
                        "shasum": "abc123"
                    }
                },
                "1.0.1": {
                    "name": "demo",
                    "version": "1.0.1",
                    "dist": {
                        "tarball": "https://registry.example/demo/-/demo-1.0.1.tgz"
                    }
                },
                "2.0.0": {
                    "name": "demo",
                    "version": "2.0.0",
                    "dist": {
                        "tarball": "https://registry.example/demo/-/demo-2.0.0.tgz"
                    }
                }
            }
        })
    }

    #[tokio::test]
    async fn lookup_artifact_returns_registry_metadata_artifact() {
        let upstream = StaticUpstream::new("demo", metadata_fixture());

        let artifact = lookup_artifact(&upstream, "demo", "1.0.0").await.unwrap();

        assert_eq!(artifact.identity(), "npm:demo@1.0.0");
        assert_eq!(artifact.filename.as_deref(), Some("demo-1.0.0.tgz"));
        assert_eq!(
            artifact.upstream_url.as_deref(),
            Some("https://registry.example/demo/-/demo-1.0.0.tgz")
        );
        assert_eq!(artifact.hashes.integrity.as_deref(), Some("sha512-allowed"));
        assert_eq!(artifact.hashes.sha512.as_deref(), Some("allowed"));
        assert_eq!(
            artifact.published_at,
            DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
                .into()
        );
    }

    #[tokio::test]
    async fn lookup_artifact_fails_when_version_is_missing() {
        let upstream = StaticUpstream::new("demo", metadata_fixture());

        let err = lookup_artifact(&upstream, "demo", "9.9.9")
            .await
            .unwrap_err();

        assert!(matches!(err, NpmError::VersionNotFound(package, version)
            if package == "demo" && version == "9.9.9"));
    }

    #[tokio::test]
    async fn npm_metadata_filters_versions_rewrites_tarballs_and_dist_tags() {
        let mut config = Config::default();
        config.server.public_base_url = "https://proxy.example".to_string();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Npm,
            name: "demo".to_string(),
            versions: vec!["1.0.1".to_string()],
            reason: "known bad".to_string(),
        });
        let upstream = StaticUpstream::new("demo", metadata_fixture());
        let checker = CleanChecker::new();

        let response = metadata_response(&config, &upstream, &checker, "demo", now())
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let versions = body["versions"].as_object().unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions.contains_key("1.0.0"));
        assert_eq!(
            body["versions"]["1.0.0"]["dist"]["tarball"],
            "https://proxy.example/npm/demo/-/demo-1.0.0.tgz"
        );
        assert_eq!(
            body["versions"]["1.0.0"]["dist"]["integrity"],
            "sha512-allowed"
        );
        assert_eq!(body["versions"]["1.0.0"]["dist"]["shasum"], "abc123");
        assert_eq!(body["dist-tags"], json!({ "stable": "1.0.0" }));
        assert_eq!(checker.batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(checker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn npm_metadata_skips_malicious_batch_for_bypass_allowlist_versions() {
        let mut config = Config::default();
        config.server.public_base_url = "https://proxy.example".to_string();
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::Npm,
            name: "demo".to_string(),
            version: "2.0.0".to_string(),
            bypass_age_gate: false,
            bypass_osv: true,
            reason: "known false positive".to_string(),
        });
        let metadata = json!({
            "name": "demo",
            "dist-tags": {
                "latest": "2.0.0",
                "stable": "1.0.0"
            },
            "time": {
                "1.0.0": "2026-06-01T00:00:00Z",
                "2.0.0": "2026-07-05T00:00:00Z"
            },
            "versions": {
                "1.0.0": {
                    "name": "demo",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.example/demo/-/demo-1.0.0.tgz"
                    }
                },
                "2.0.0": {
                    "name": "demo",
                    "version": "2.0.0",
                    "dist": {
                        "tarball": "https://registry.example/demo/-/demo-2.0.0.tgz"
                    }
                }
            }
        });
        let upstream = StaticUpstream::new("demo", metadata);
        let checker = CleanChecker::new();

        let response = metadata_response(&config, &upstream, &checker, "demo", now())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let versions = body["versions"].as_object().unwrap();

        assert!(versions.contains_key("1.0.0"));
        assert!(!versions.contains_key("2.0.0"));
        assert_eq!(body["dist-tags"], json!({ "stable": "1.0.0" }));
        assert_eq!(checker.batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(checker.calls.load(Ordering::SeqCst), 0);
        assert_eq!(checker.batch_identities(), vec!["npm:demo@1.0.0"]);
    }

    #[tokio::test]
    async fn npm_metadata_short_malicious_batch_results_fail_closed() {
        let config = Config::default();
        let metadata = json!({
            "name": "demo",
            "dist-tags": {
                "latest": "1.0.1",
                "stable": "1.0.0"
            },
            "time": {
                "1.0.0": "2026-06-01T00:00:00Z",
                "1.0.1": "2026-06-01T00:00:00Z"
            },
            "versions": {
                "1.0.0": {
                    "name": "demo",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.example/demo/-/demo-1.0.0.tgz"
                    }
                },
                "1.0.1": {
                    "name": "demo",
                    "version": "1.0.1",
                    "dist": {
                        "tarball": "https://registry.example/demo/-/demo-1.0.1.tgz"
                    }
                }
            }
        });
        let upstream = StaticUpstream::new("demo", metadata);

        let response = metadata_response(&config, &upstream, &ShortBatchChecker, "demo", now())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response.body).unwrap();

        assert!(body["versions"].as_object().unwrap().is_empty());
        assert_eq!(body["dist-tags"], json!({}));
    }

    #[tokio::test]
    async fn npm_metadata_preserves_scoped_package_names_in_proxy_urls() {
        let mut config = Config::default();
        config.server.public_base_url = "https://proxy.example/".to_string();
        let metadata = json!({
            "name": "@babel/core",
            "dist-tags": { "latest": "7.24.0" },
            "time": { "7.24.0": "2026-06-01T00:00:00Z" },
            "versions": {
                "7.24.0": {
                    "name": "@babel/core",
                    "version": "7.24.0",
                    "dist": {
                        "tarball": "https://registry.example/@babel/core/-/core-7.24.0.tgz"
                    }
                }
            }
        });
        let upstream = StaticUpstream::new("@babel/core", metadata);
        let checker = CleanChecker::new();

        let response = metadata_response(&config, &upstream, &checker, "@babel/core", now())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            body["versions"]["7.24.0"]["dist"]["tarball"],
            "https://proxy.example/npm/@babel/core/-/core-7.24.0.tgz"
        );
    }

    #[tokio::test]
    async fn npm_artifact_allowed_tarball_redirects_to_upstream() {
        let config = Config::default();
        let metadata = json!({
            "name": "@babel/core",
            "time": { "7.24.0": "2026-06-01T00:00:00Z" },
            "versions": {
                "7.24.0": {
                    "name": "@babel/core",
                    "version": "7.24.0",
                    "dist": {
                        "tarball": "https://registry.example/@babel/core/-/core-7.24.0.tgz"
                    }
                }
            }
        });
        let upstream = StaticUpstream::new("@babel/core", metadata);
        let checker = CleanChecker::new();

        let response = artifact_response(
            &config,
            &upstream,
            &checker,
            "@babel/core",
            "core-7.24.0.tgz",
            now(),
        )
        .await
        .unwrap();

        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            vec![(
                "location".to_string(),
                "https://registry.example/@babel/core/-/core-7.24.0.tgz".to_string()
            )]
        );
        assert_eq!(checker.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn npm_artifact_proxy_streams_upstream_bytes_and_headers() {
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        let (tarball_url, request) = serve_artifact_once(
            "HTTP/1.1 200 OK\r\n\
             content-type: application/octet-stream\r\n\
             content-length: 11\r\n\
             etag: \"npm\"\r\n\
             connection: close\r\n\
             \r\n\
             npm-tarball",
        )
        .await;
        config.artifacts.trusted_origins.push(
            reqwest::Url::parse(&tarball_url)
                .unwrap()
                .origin()
                .ascii_serialization(),
        );
        let metadata = json!({
            "name": "demo",
            "time": { "1.0.0": "2026-06-01T00:00:00Z" },
            "versions": {
                "1.0.0": {
                    "name": "demo",
                    "version": "1.0.0",
                    "dist": { "tarball": tarball_url }
                }
            }
        });
        let upstream = StaticUpstream::new("demo", metadata);
        let checker = CleanChecker::new();
        let delivery = ArtifactDeliveryClient::for_config(&config);
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=0-10".parse().unwrap());

        let response = artifact_delivery_response(
            &config,
            &upstream,
            &checker,
            NpmArtifactRoute {
                package: "demo",
                tarball: "demo-1.0.0.tgz",
            },
            now(),
            ArtifactDeliveryOptions::with_request_headers(&delivery, &headers),
        )
        .await
        .unwrap()
        .into_registry_response()
        .await;
        let upstream_request = request.await.unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"npm-tarball");
        assert_header(&response, "content-type", "application/octet-stream");
        assert_header(&response, "content-length", "11");
        assert_header(&response, "etag", "\"npm\"");
        assert!(upstream_request.contains("range: bytes=0-10"));
        assert_eq!(checker.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn npm_artifact_rejects_unscoped_tarball_basename_mismatch() {
        let config = Config::default();
        let metadata = json!({
            "name": "demo",
            "time": { "1.0.0": "2026-06-01T00:00:00Z" },
            "versions": {
                "1.0.0": {
                    "name": "demo",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.example/demo/-/demo-1.0.0.tgz"
                    }
                }
            }
        });
        let upstream = StaticUpstream::new("demo", metadata);
        let checker = CleanChecker::new();

        let response = artifact_response(
            &config,
            &upstream,
            &checker,
            "demo",
            "anything-1.0.0.tgz",
            now(),
        )
        .await
        .unwrap_or_else(|err| error_response(&err));

        assert_eq!(response.status, 404);
        assert!(response.headers.iter().all(|(name, _)| name != "location"));
        assert_eq!(checker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn npm_artifact_rejects_scoped_tarball_basename_mismatch() {
        let config = Config::default();
        let metadata = json!({
            "name": "@babel/core",
            "time": { "7.24.0": "2026-06-01T00:00:00Z" },
            "versions": {
                "7.24.0": {
                    "name": "@babel/core",
                    "version": "7.24.0",
                    "dist": {
                        "tarball": "https://registry.example/@babel/core/-/core-7.24.0.tgz"
                    }
                }
            }
        });
        let upstream = StaticUpstream::new("@babel/core", metadata);
        let checker = CleanChecker::new();

        let response = artifact_response(
            &config,
            &upstream,
            &checker,
            "@babel/core",
            "anything-7.24.0.tgz",
            now(),
        )
        .await
        .unwrap_or_else(|err| error_response(&err));

        assert_eq!(response.status, 404);
        assert!(response.headers.iter().all(|(name, _)| name != "location"));
        assert_eq!(checker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn npm_artifact_blocked_tarball_returns_structured_403() {
        let mut config = Config::default();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Npm,
            name: "demo".to_string(),
            versions: vec!["1.0.0".to_string()],
            reason: "known bad".to_string(),
        });
        let metadata = json!({
            "name": "demo",
            "time": { "1.0.0": "2026-06-01T00:00:00Z" },
            "versions": {
                "1.0.0": {
                    "name": "demo",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.example/demo/-/demo-1.0.0.tgz"
                    }
                }
            }
        });
        let upstream = StaticUpstream::new("demo", metadata);
        let checker = CleanChecker::new();

        let response = artifact_response(
            &config,
            &upstream,
            &checker,
            "demo",
            "demo-1.0.0.tgz",
            now(),
        )
        .await
        .unwrap();
        let body: Decision = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status, 403);
        assert!(!body.allowed);
        assert_eq!(body.package, "npm:demo@1.0.0");
    }

    #[tokio::test]
    async fn npm_artifact_proxy_blocked_tarball_does_not_fetch_upstream_bytes() {
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Npm,
            name: "demo".to_string(),
            versions: vec!["1.0.0".to_string()],
            reason: "known bad".to_string(),
        });
        let (tarball_url, request) = serve_artifact_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nbytes",
        )
        .await;
        let metadata = json!({
            "name": "demo",
            "time": { "1.0.0": "2026-06-01T00:00:00Z" },
            "versions": {
                "1.0.0": {
                    "name": "demo",
                    "version": "1.0.0",
                    "dist": { "tarball": tarball_url }
                }
            }
        });
        let upstream = StaticUpstream::new("demo", metadata);
        let checker = CleanChecker::new();

        let response = artifact_response(
            &config,
            &upstream,
            &checker,
            "demo",
            "demo-1.0.0.tgz",
            now(),
        )
        .await
        .unwrap();
        let body: Decision = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status, 403);
        assert!(!body.allowed);
        assert!(timeout(Duration::from_millis(100), request).await.is_err());
    }

    #[test]
    fn infers_versions_from_unscoped_and_scoped_tarball_names() {
        assert_eq!(
            infer_version_from_tarball("lodash", "lodash-4.17.21.tgz"),
            Some("4.17.21".to_string())
        );
        assert_eq!(
            infer_version_from_tarball("@babel/core", "core-7.24.0.tgz"),
            Some("7.24.0".to_string())
        );
        assert_eq!(
            infer_version_from_tarball("left-pad", "left-pad-1.3.0-beta.1.tgz"),
            Some("1.3.0-beta.1".to_string())
        );
    }

    async fn serve_artifact_once(
        response: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4096];
            let bytes = stream.read(&mut buffer).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buffer[..bytes]).to_ascii_lowercase()
        });
        (format!("http://{address}/demo/-/demo-1.0.0.tgz"), handle)
    }

    fn assert_header(response: &RegistryResponse, name: &str, expected: &str) {
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str()),
            Some(expected)
        );
    }

    #[test]
    fn encodes_scoped_package_for_registry_metadata_fetch() {
        assert_eq!(encode_package_for_registry("@babel/core"), "@babel%2Fcore");
        assert_eq!(encode_package_for_registry("lodash"), "lodash");
    }

    #[tokio::test]
    async fn too_young_metadata_version_is_removed() {
        let config = Config::default();
        let checker = CleanChecker::new();
        let mut metadata = metadata_fixture();
        metadata["versions"]
            .as_object_mut()
            .unwrap()
            .remove("1.0.1");
        let upstream = StaticUpstream::new("demo", metadata);

        let response = metadata_response(&config, &upstream, &checker, "demo", now())
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&response.body).unwrap();

        assert!(body["versions"].as_object().unwrap().contains_key("1.0.0"));
        assert!(!body["versions"].as_object().unwrap().contains_key("2.0.0"));
    }

    #[test]
    fn package_artifact_uses_npm_ecosystem() {
        let artifact = package_artifact(
            "@babel/core",
            "7.24.0",
            Some(now() - ChronoDuration::hours(100)),
        );
        assert_eq!(artifact.ecosystem, Ecosystem::Npm);
        assert_eq!(artifact.name, "@babel/core");
        assert_eq!(artifact.version, "7.24.0");
    }
}
