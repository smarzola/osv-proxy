//! Maven Repository Layout metadata, identity, and version semantics.

use crate::artifact::{Artifact, ArtifactHashes, Ecosystem};
use crate::artifacts::{ArtifactDeliveryError, ArtifactDeliveryOptions, ArtifactDeliveryResponse};
use crate::config::{ArtifactBehavior, Config};
use crate::malicious::MaliciousChecker;
use crate::policy::{Decision, PolicyEngine};
use crate::response::RegistryResponse;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{Stream, StreamExt};
use quick_xml::de::from_str;
use reqwest::{Client, StatusCode, header};
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::cmp::Ordering;
use std::fmt::Display;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_POM_BYTES: usize = 1024 * 1024;
const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const METADATA_ENRICHMENT_CONCURRENCY: usize = 16;

#[derive(Debug, Clone)]
pub struct MavenRepositoryClient {
    repository_url: String,
    client: Client,
}

impl MavenRepositoryClient {
    pub fn new(repository_url: &str) -> Self {
        Self {
            repository_url: repository_url.trim_end_matches('/').to_string(),
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("Maven HTTP client should build with static timeout configuration"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenPomMetadata {
    pub body: String,
    pub last_modified: Option<String>,
    pub sha256: Option<String>,
    pub upstream_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenPomHead {
    pub last_modified: Option<String>,
    pub sha256: Option<String>,
    pub upstream_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenRawMetadata {
    pub body: String,
}

#[async_trait]
pub trait MavenMetadataProvider: Send + Sync {
    async fn fetch_pom(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
    ) -> Result<MavenPomMetadata, MavenError>;

    async fn fetch_metadata(&self, _relative_path: &str) -> Result<MavenRawMetadata, MavenError> {
        Err(MavenError::UnsupportedMetadataRoute)
    }

    async fn fetch_pom_head(
        &self,
        _group_id: &str,
        _artifact_id: &str,
        _version: &str,
    ) -> Result<MavenPomHead, MavenError> {
        Err(MavenError::UnsupportedPomHead)
    }

    async fn validate_artifact(&self, _relative_path: &str) -> Result<(), MavenError> {
        Ok(())
    }
}

#[async_trait]
impl MavenMetadataProvider for MavenRepositoryClient {
    async fn fetch_pom(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
    ) -> Result<MavenPomMetadata, MavenError> {
        validate_coordinate(group_id, artifact_id, version)?;
        let url = pom_url(&self.repository_url, group_id, artifact_id, version);
        let response = self.client.get(&url).send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(MavenError::VersionNotFound(format!(
                "{group_id}:{artifact_id}@{version}"
            )));
        }
        let response = response.error_for_status()?;
        let last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let sha256 = response
            .headers()
            .get("x-checksum-sha256")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        ensure_pom_content_length(response.content_length())?;
        let body = collect_bounded_pom(response.bytes_stream()).await?;
        let body = String::from_utf8(body)
            .map_err(|error| MavenError::InvalidPomEncoding(error.to_string()))?;
        Ok(MavenPomMetadata {
            body,
            last_modified,
            sha256,
            upstream_url: url,
        })
    }

    async fn fetch_metadata(&self, relative_path: &str) -> Result<MavenRawMetadata, MavenError> {
        if relative_path.is_empty()
            || relative_path.starts_with('/')
            || relative_path
                .split('/')
                .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        {
            return Err(MavenError::InvalidMetadataPath(relative_path.to_string()));
        }
        let url = format!("{}/{}", self.repository_url, relative_path);
        let response = self.client.get(url).send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(MavenError::MetadataNotFound(relative_path.to_string()));
        }
        let response = response.error_for_status()?;
        ensure_content_length(response.content_length(), MAX_METADATA_BYTES, "metadata")?;
        let body = collect_bounded_body(
            response.bytes_stream(),
            MAX_METADATA_BYTES,
            "Maven metadata",
        )
        .await?;
        let body = String::from_utf8(body)
            .map_err(|error| MavenError::InvalidMetadataEncoding(error.to_string()))?;
        Ok(MavenRawMetadata { body })
    }

    async fn fetch_pom_head(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
    ) -> Result<MavenPomHead, MavenError> {
        validate_coordinate(group_id, artifact_id, version)?;
        let url = pom_url(&self.repository_url, group_id, artifact_id, version);
        let response = self.client.head(&url).send().await?;
        if matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::GONE) {
            return Err(MavenError::VersionNotFound(format!(
                "{group_id}:{artifact_id}@{version}"
            )));
        }
        let response = response.error_for_status()?;
        Ok(MavenPomHead {
            last_modified: response
                .headers()
                .get(header::LAST_MODIFIED)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            sha256: response
                .headers()
                .get("x-checksum-sha256")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            upstream_url: url,
        })
    }

    async fn validate_artifact(&self, relative_path: &str) -> Result<(), MavenError> {
        validate_relative_path(relative_path)?;
        let response = self
            .client
            .head(format!("{}/{}", self.repository_url, relative_path))
            .send()
            .await?;
        if matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::GONE) {
            return Err(MavenError::ArtifactNotFound(relative_path.to_string()));
        }
        response.error_for_status()?;
        Ok(())
    }
}

fn validate_relative_path(relative_path: &str) -> Result<(), MavenError> {
    if relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.contains('%')
        || relative_path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(MavenError::InvalidArtifactPath(relative_path.to_string()));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct PomProject {
    #[serde(rename = "groupId")]
    group_id: Option<String>,
    #[serde(rename = "artifactId")]
    artifact_id: String,
    version: Option<String>,
    parent: Option<PomParent>,
}

#[derive(Debug, Deserialize)]
struct PomParent {
    #[serde(rename = "groupId")]
    group_id: String,
    version: String,
}

pub async fn lookup_artifact(
    provider: &dyn MavenMetadataProvider,
    package: &str,
    version: &str,
) -> Result<Artifact, MavenError> {
    let (group_id, artifact_id) = parse_package_name(package)?;
    let metadata = provider.fetch_pom(group_id, artifact_id, version).await?;
    let project: PomProject =
        from_str(&metadata.body).map_err(|error| MavenError::InvalidPom(error.to_string()))?;
    let effective_group = project
        .group_id
        .as_deref()
        .or_else(|| {
            project
                .parent
                .as_ref()
                .map(|parent| parent.group_id.as_str())
        })
        .ok_or_else(|| MavenError::InvalidPom("POM has no effective groupId".to_string()))?;
    let effective_version = project
        .version
        .as_deref()
        .or_else(|| {
            project
                .parent
                .as_ref()
                .map(|parent| parent.version.as_str())
        })
        .ok_or_else(|| MavenError::InvalidPom("POM has no effective version".to_string()))?;
    if effective_group != group_id
        || project.artifact_id != artifact_id
        || effective_version != version
    {
        return Err(MavenError::CoordinateMismatch {
            expected: format!("{group_id}:{artifact_id}@{version}"),
            actual: format!(
                "{effective_group}:{}@{effective_version}",
                project.artifact_id
            ),
        });
    }
    let published_at = metadata
        .last_modified
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc2822(value).ok())
        .map(|value| value.with_timezone(&Utc));
    Ok(Artifact {
        ecosystem: Ecosystem::Maven,
        name: package.to_string(),
        version: version.to_string(),
        filename: Some(format!("{artifact_id}-{version}.pom")),
        upstream_url: Some(metadata.upstream_url),
        published_at,
        hashes: ArtifactHashes {
            sha256: metadata.sha256,
            ..ArtifactHashes::default()
        },
    })
}

fn ensure_pom_content_length(content_length: Option<u64>) -> Result<(), MavenError> {
    ensure_content_length(content_length, MAX_POM_BYTES, "POM")
}

async fn collect_bounded_pom<S, T, E>(mut stream: S) -> Result<Vec<u8>, MavenError>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    T: AsRef<[u8]>,
    E: Display,
{
    collect_bounded_body(&mut stream, MAX_POM_BYTES, "Maven POM").await
}

fn ensure_content_length(
    content_length: Option<u64>,
    limit: usize,
    kind: &'static str,
) -> Result<(), MavenError> {
    if content_length.is_some_and(|length| length > limit as u64) {
        return Err(MavenError::BodyTooLarge { kind, limit });
    }
    Ok(())
}

async fn collect_bounded_body<S, T, E>(
    mut stream: S,
    limit: usize,
    kind: &'static str,
) -> Result<Vec<u8>, MavenError>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    T: AsRef<[u8]>,
    E: Display,
{
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| MavenError::BodyRead(error.to_string()))?;
        if body.len().saturating_add(chunk.as_ref().len()) > limit {
            return Err(MavenError::BodyTooLarge { kind, limit });
        }
        body.extend_from_slice(chunk.as_ref());
    }
    Ok(body)
}

#[derive(Debug, Deserialize)]
struct MavenMetadataDocument {
    #[serde(rename = "groupId")]
    group_id: String,
    #[serde(rename = "artifactId")]
    artifact_id: String,
    versioning: MavenVersioning,
}

#[derive(Debug, Deserialize)]
struct MavenMetadataProbe {
    #[serde(rename = "groupId")]
    group_id: Option<String>,
    #[serde(rename = "artifactId")]
    artifact_id: Option<String>,
    versioning: Option<MavenVersioning>,
    plugins: Option<MavenPlugins>,
}

#[derive(Debug, Deserialize)]
struct MavenPlugins {
    #[serde(rename = "plugin", default)]
    values: Vec<MavenPlugin>,
}

#[derive(Debug, Deserialize)]
struct MavenPlugin {
    prefix: String,
    #[serde(rename = "artifactId")]
    artifact_id: String,
}

#[derive(Debug, Deserialize)]
struct MavenVersioning {
    versions: MavenVersions,
    #[serde(rename = "lastUpdated")]
    last_updated: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MavenVersions {
    #[serde(rename = "version", default)]
    values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataChecksum {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl MetadataChecksum {
    pub fn from_suffix(suffix: &str) -> Option<Self> {
        match suffix {
            "md5" => Some(Self::Md5),
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

pub async fn filtered_metadata_response(
    config: &Config,
    provider: &dyn MavenMetadataProvider,
    checker: &dyn MaliciousChecker,
    group_id: &str,
    artifact_id: &str,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, MavenError> {
    validate_coordinate(group_id, artifact_id, "placeholder")?;
    let relative_path = format!(
        "{}/{artifact_id}/maven-metadata.xml",
        group_id.replace('.', "/")
    );
    let raw = provider.fetch_metadata(&relative_path).await?;
    filtered_metadata_from_raw(config, provider, checker, group_id, artifact_id, now, raw).await
}

async fn filtered_metadata_from_raw(
    config: &Config,
    provider: &dyn MavenMetadataProvider,
    checker: &dyn MaliciousChecker,
    group_id: &str,
    artifact_id: &str,
    now: DateTime<Utc>,
    raw: MavenRawMetadata,
) -> Result<RegistryResponse, MavenError> {
    let document: MavenMetadataDocument =
        from_str(&raw.body).map_err(|error| MavenError::InvalidMetadata(error.to_string()))?;
    if document.group_id != group_id || document.artifact_id != artifact_id {
        return Err(MavenError::MetadataCoordinateMismatch {
            expected: format!("{group_id}:{artifact_id}"),
            actual: format!("{}:{}", document.group_id, document.artifact_id),
        });
    }
    let mut versions = document.versioning.versions.values;
    if versions.is_empty() {
        return Err(MavenError::InvalidMetadata(
            "artifact metadata has no versions".to_string(),
        ));
    }
    for version in &versions {
        validate_coordinate(group_id, artifact_id, version)?;
        compare_versions(version, version)?;
        if version.to_ascii_uppercase().ends_with("-SNAPSHOT") {
            return Err(MavenError::SnapshotsUnsupported(version.clone()));
        }
    }
    versions.sort_by(|left, right| {
        compare_versions(left, right)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.cmp(right))
    });
    versions.dedup();

    let package = format!("{group_id}:{artifact_id}");
    let enriched = futures_util::stream::iter(versions.into_iter().map(|version| {
        let package = package.clone();
        async move {
            let result = lookup_artifact(provider, &package, &version).await;
            (version, result)
        }
    }))
    .buffered(METADATA_ENRICHMENT_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    let mut artifacts = Vec::new();
    for (version, result) in enriched {
        match result {
            Ok(artifact) => artifacts.push(artifact),
            Err(MavenError::VersionNotFound(_)) => {}
            Err(error) => {
                return Err(MavenError::VersionEnrichment {
                    version,
                    message: error.to_string(),
                });
            }
        }
    }
    let decisions = evaluate_artifacts(config, checker, &artifacts, now).await;
    let retained = artifacts
        .iter()
        .zip(decisions)
        .filter_map(|(artifact, decision)| decision.allowed.then_some(artifact.version.clone()))
        .collect::<Vec<_>>();
    let body = render_metadata(
        group_id,
        artifact_id,
        &retained,
        document.versioning.last_updated.as_deref(),
    );
    Ok(metadata_body_response(body))
}

pub async fn metadata_route_response(
    config: &Config,
    provider: &dyn MavenMetadataProvider,
    checker: &dyn MaliciousChecker,
    relative_path: &str,
    checksum: Option<MetadataChecksum>,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, MavenError> {
    let raw = provider.fetch_metadata(relative_path).await?;
    let probe: MavenMetadataProbe =
        from_str(&raw.body).map_err(|error| MavenError::InvalidMetadata(error.to_string()))?;
    let response = match (
        probe.group_id,
        probe.artifact_id,
        probe.versioning,
        probe.plugins,
    ) {
        (Some(_), Some(_), Some(_), None) => {
            let document: MavenMetadataDocument = from_str(&raw.body)
                .map_err(|error| MavenError::InvalidMetadata(error.to_string()))?;
            let expected_path = format!(
                "{}/{}/maven-metadata.xml",
                document.group_id.replace('.', "/"),
                document.artifact_id
            );
            if relative_path != expected_path {
                return Err(MavenError::InvalidMetadataPath(relative_path.to_string()));
            }
            filtered_metadata_from_raw(
                config,
                provider,
                checker,
                &document.group_id,
                &document.artifact_id,
                now,
                raw,
            )
            .await?
        }
        (group_id, None, None, Some(plugins)) => {
            if plugins.values.is_empty()
                || plugins.values.iter().any(|plugin| {
                    validate_metadata_token(&plugin.prefix).is_err()
                        || validate_metadata_token(&plugin.artifact_id).is_err()
                })
            {
                return Err(MavenError::InvalidMetadata(
                    "group metadata has invalid plugin entries".to_string(),
                ));
            }
            let _ = group_id;
            RegistryResponse {
                status: 200,
                headers: vec![
                    ("content-type".to_string(), "application/xml".to_string()),
                    ("cache-control".to_string(), "no-cache".to_string()),
                ],
                body: raw.body.into_bytes(),
            }
        }
        _ => {
            return Err(MavenError::InvalidMetadata(
                "metadata mixes group and artifact-level fields".to_string(),
            ));
        }
    };
    Ok(checksum.map_or_else(
        || response.clone(),
        |kind| checksum_response(&response, kind),
    ))
}

fn validate_metadata_token(value: &str) -> Result<(), MavenError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(MavenError::InvalidMetadata(format!(
            "invalid plugin metadata token {value}"
        )));
    }
    Ok(())
}

pub async fn group_metadata_response(
    provider: &dyn MavenMetadataProvider,
    relative_path: &str,
) -> Result<RegistryResponse, MavenError> {
    let raw = provider.fetch_metadata(relative_path).await?;
    Ok(RegistryResponse {
        status: 200,
        headers: vec![
            ("content-type".to_string(), "application/xml".to_string()),
            ("cache-control".to_string(), "no-cache".to_string()),
        ],
        body: raw.body.into_bytes(),
    })
}

fn render_metadata(
    group_id: &str,
    artifact_id: &str,
    versions: &[String],
    last_updated: Option<&str>,
) -> Vec<u8> {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n");
    xml.push_str(&format!("  <groupId>{}</groupId>\n", xml_escape(group_id)));
    xml.push_str(&format!(
        "  <artifactId>{}</artifactId>\n  <versioning>\n",
        xml_escape(artifact_id)
    ));
    if let Some(latest) = versions.last() {
        xml.push_str(&format!("    <latest>{}</latest>\n", xml_escape(latest)));
        xml.push_str(&format!("    <release>{}</release>\n", xml_escape(latest)));
    }
    xml.push_str("    <versions>\n");
    for version in versions {
        xml.push_str(&format!(
            "      <version>{}</version>\n",
            xml_escape(version)
        ));
    }
    xml.push_str("    </versions>\n");
    if let Some(last_updated) = last_updated {
        xml.push_str(&format!(
            "    <lastUpdated>{}</lastUpdated>\n",
            xml_escape(last_updated)
        ));
    }
    xml.push_str("  </versioning>\n</metadata>\n");
    xml.into_bytes()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn metadata_body_response(body: Vec<u8>) -> RegistryResponse {
    let etag = format!("\"{}\"", hex_digest::<Sha256>(&body));
    RegistryResponse {
        status: 200,
        headers: vec![
            ("content-type".to_string(), "application/xml".to_string()),
            ("cache-control".to_string(), "no-cache".to_string()),
            ("etag".to_string(), etag),
        ],
        body,
    }
}

pub fn checksum_response(
    metadata: &RegistryResponse,
    checksum: MetadataChecksum,
) -> RegistryResponse {
    let digest = match checksum {
        MetadataChecksum::Md5 => format!("{:x}", md5::compute(&metadata.body)),
        MetadataChecksum::Sha1 => hex_digest::<Sha1>(&metadata.body),
        MetadataChecksum::Sha256 => hex_digest::<Sha256>(&metadata.body),
        MetadataChecksum::Sha512 => hex_digest::<Sha512>(&metadata.body),
    };
    RegistryResponse {
        status: 200,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body: format!("{digest}\n").into_bytes(),
    }
}

fn hex_digest<D: Digest + Default>(body: &[u8]) -> String {
    let mut digest = D::new();
    digest.update(body);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn apply_if_none_match(
    mut response: RegistryResponse,
    if_none_match: Option<&str>,
) -> RegistryResponse {
    if response.status != 200 {
        return response;
    }
    let etag = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("etag"))
        .map(|(_, value)| value.as_str());
    if if_none_match.is_some_and(|value| {
        value.split(',').map(str::trim).any(|candidate| {
            candidate == "*"
                || etag.is_some_and(|etag| weak_entity_tag(candidate) == weak_entity_tag(etag))
        })
    }) {
        response.status = 304;
        response.body.clear();
    }
    response
}

fn weak_entity_tag(value: &str) -> &str {
    value.strip_prefix("W/").unwrap_or(value)
}

pub fn error_response(error: &MavenError) -> RegistryResponse {
    let status = match error {
        MavenError::MetadataNotFound(_)
        | MavenError::VersionNotFound(_)
        | MavenError::ArtifactNotFound(_)
        | MavenError::Delivery(ArtifactDeliveryError::UpstreamStatus(404 | 410)) => 404,
        MavenError::Denied(_) => 403,
        _ => 502,
    };
    if let MavenError::Denied(decision) = error {
        return RegistryResponse::json(
            403,
            &serde_json::to_value(decision).expect("Maven decision should serialize"),
        )
        .expect("Maven denial should serialize");
    }
    RegistryResponse::json(
        status,
        &serde_json::json!({
            "allowed": false,
            "reason": "maven_upstream_error",
            "message": error.to_string()
        }),
    )
    .expect("static Maven error response should serialize")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenReleaseRoute {
    pub relative_path: String,
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub filename: String,
}

pub fn parse_release_path(relative_path: &str) -> Result<MavenReleaseRoute, MavenError> {
    validate_relative_path(relative_path)?;
    let segments = relative_path.split('/').collect::<Vec<_>>();
    if segments.len() < 4 {
        return Err(MavenError::InvalidArtifactPath(relative_path.to_string()));
    }
    let artifact_id = segments[segments.len() - 3];
    let version = segments[segments.len() - 2];
    let filename = segments[segments.len() - 1];
    let group_segments = &segments[..segments.len() - 3];
    if group_segments.iter().any(|segment| {
        !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }) {
        return Err(MavenError::InvalidArtifactPath(relative_path.to_string()));
    }
    let group_id = group_segments.join(".");
    validate_coordinate(&group_id, artifact_id, version)?;
    if version.to_ascii_uppercase().ends_with("-SNAPSHOT") {
        return Err(MavenError::SnapshotsUnsupported(version.to_string()));
    }
    let prefix = format!("{artifact_id}-{version}");
    let suffix = filename
        .strip_prefix(&prefix)
        .ok_or_else(|| MavenError::InvalidArtifactPath(relative_path.to_string()))?;
    let suffix_valid = if let Some(extension) = suffix.strip_prefix('.') {
        !extension.is_empty()
    } else if let Some(classified) = suffix.strip_prefix('-') {
        classified
            .split_once('.')
            .is_some_and(|(classifier, extension)| !classifier.is_empty() && !extension.is_empty())
    } else {
        false
    };
    if !suffix_valid
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
    {
        return Err(MavenError::InvalidArtifactPath(relative_path.to_string()));
    }
    Ok(MavenReleaseRoute {
        relative_path: relative_path.to_string(),
        group_id,
        artifact_id: artifact_id.to_string(),
        version: version.to_string(),
        filename: filename.to_string(),
    })
}

pub async fn artifact_delivery_response(
    config: &Config,
    provider: &dyn MavenMetadataProvider,
    checker: &dyn MaliciousChecker,
    route: &MavenReleaseRoute,
    now: DateTime<Utc>,
    delivery: ArtifactDeliveryOptions<'_>,
) -> Result<ArtifactDeliveryResponse, MavenError> {
    let package = format!("{}:{}", route.group_id, route.artifact_id);
    let pom = provider
        .fetch_pom_head(&route.group_id, &route.artifact_id, &route.version)
        .await?;
    let published_at = pom
        .last_modified
        .as_deref()
        .and_then(|value| DateTime::parse_from_rfc2822(value).ok())
        .map(|value| value.with_timezone(&Utc));
    let canonical_pom = format!("{}-{}.pom", route.artifact_id, route.version);
    let mut artifact = Artifact::package(Ecosystem::Maven, &package, &route.version, published_at);
    artifact.filename = Some(route.filename.clone());
    artifact.upstream_url = Some(format!(
        "{}/{}",
        config.upstreams.maven.repository_url.trim_end_matches('/'),
        route.relative_path
    ));
    if route.filename == canonical_pom {
        artifact.hashes.sha256 = pom.sha256;
    }
    let decision = PolicyEngine::new(config)
        .evaluate(&artifact, now, checker)
        .await;
    if !decision.allowed {
        return Err(MavenError::Denied(Box::new(decision)));
    }
    if config.artifacts.behavior == ArtifactBehavior::Redirect && route.filename != canonical_pom {
        provider.validate_artifact(&route.relative_path).await?;
    }
    let upstream_url = artifact
        .upstream_url
        .expect("Maven artifact has upstream URL");
    if delivery.head {
        delivery
            .client
            .deliver_head(config, upstream_url, delivery.request_headers)
            .await
            .map_err(MavenError::Delivery)
    } else {
        delivery
            .client
            .deliver(config, upstream_url, delivery.request_headers)
            .await
            .map_err(MavenError::Delivery)
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
                "Maven OSV batch returned {} results for {} artifacts",
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
                        format!("Maven OSV batch result missing for {}", artifact.identity())
                    }),
                    Err(error) => Err(error.clone()),
                });
            policy.evaluate_with_malicious_result(artifact, now, result)
        })
        .collect()
}

pub fn parse_package_name(package: &str) -> Result<(&str, &str), MavenError> {
    let (group_id, artifact_id) = package
        .split_once(':')
        .ok_or_else(|| MavenError::InvalidPackageName(package.to_string()))?;
    if artifact_id.contains(':') {
        return Err(MavenError::InvalidPackageName(package.to_string()));
    }
    validate_coordinate(group_id, artifact_id, "placeholder")?;
    Ok((group_id, artifact_id))
}

pub fn validate_coordinate(
    group_id: &str,
    artifact_id: &str,
    version: &str,
) -> Result<(), MavenError> {
    let valid = |value: &str, allow_dots: bool| {
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || byte == b'-'
                    || byte == b'_'
                    || byte == b'+'
                    || (allow_dots && byte == b'.')
            })
    };
    if !valid(group_id, true) || !valid(artifact_id, true) || !valid(version, true) {
        return Err(MavenError::InvalidCoordinate(format!(
            "{group_id}:{artifact_id}@{version}"
        )));
    }
    Ok(())
}

pub fn pom_url(repository_url: &str, group_id: &str, artifact_id: &str, version: &str) -> String {
    format!(
        "{}/{}/{}/{}/{}-{}.pom",
        repository_url.trim_end_matches('/'),
        group_id.replace('.', "/"),
        artifact_id,
        version,
        artifact_id,
        version
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionToken {
    prefix: char,
    value: String,
    is_null: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MavenVersion(Vec<VersionToken>);

impl MavenVersion {
    fn parse(value: &str) -> Result<Self, MavenError> {
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == b'/')
        {
            return Err(MavenError::InvalidVersion(value.to_string()));
        }
        let mut segments = Vec::new();
        let mut start = 0;
        let bytes = value.as_bytes();
        let mut prefix = '\0';
        for (index, byte) in bytes.iter().enumerate() {
            if matches!(byte, b'.' | b'-') {
                segments.push((prefix, &value[start..index]));
                prefix = char::from(*byte);
                start = index + 1;
            }
        }
        segments.push((prefix, &value[start..]));

        let mut tokens = Vec::new();
        for (segment_prefix, segment) in segments {
            let mut split_points = Vec::new();
            let segment_bytes = segment.as_bytes();
            for index in 1..segment_bytes.len() {
                if segment_bytes[index - 1].is_ascii_digit()
                    != segment_bytes[index].is_ascii_digit()
                {
                    split_points.push(index);
                }
            }
            split_points.push(segment.len());
            let mut previous = 0;
            for (position, end) in split_points.into_iter().enumerate() {
                let token_prefix = if position == 0 { segment_prefix } else { '-' };
                let followed_by_transition = end != segment.len();
                let normalized = normalize_token(&segment[previous..end], followed_by_transition);
                tokens.push(VersionToken {
                    prefix: token_prefix,
                    value: normalized,
                    is_null: false,
                });
                previous = end;
            }
        }
        let mut index = tokens.len() as isize - 1;
        while index > 0 {
            if matches!(tokens[index as usize].value.as_str(), "0" | "") {
                tokens.remove(index as usize);
                index -= 1;
                continue;
            }
            while index >= 0 && tokens[index as usize].prefix != '-' {
                index -= 1;
            }
            index -= 1;
        }
        Ok(Self(tokens))
    }
}

fn normalize_token(value: &str, followed_by_transition: bool) -> String {
    let mut value = if value.is_empty() { "0" } else { value }.to_ascii_lowercase();
    value = match value.as_str() {
        "cr" => "rc".to_string(),
        "ga" | "final" | "release" => String::new(),
        "a" if followed_by_transition => "alpha".to_string(),
        "b" if followed_by_transition => "beta".to_string(),
        "m" if followed_by_transition => "milestone".to_string(),
        _ => value,
    };
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.trim_start_matches('0').to_string().or_zero()
    } else {
        value
    }
}

trait EmptyNumericToken {
    fn or_zero(self) -> String;
}

impl EmptyNumericToken for String {
    fn or_zero(self) -> String {
        if self.is_empty() {
            "0".to_string()
        } else {
            self
        }
    }
}

pub fn compare_versions(left: &str, right: &str) -> Result<Ordering, MavenError> {
    let left = MavenVersion::parse(left)?;
    let right = MavenVersion::parse(right)?;
    for index in 0..left.0.len().max(right.0.len()) {
        let left_token = left
            .0
            .get(index)
            .cloned()
            .unwrap_or_else(|| null_token(&right.0[index]));
        let right_token = right
            .0
            .get(index)
            .cloned()
            .unwrap_or_else(|| null_token(&left.0[index]));
        let order = compare_tokens(&left_token, &right_token);
        if order != Ordering::Equal {
            return Ok(order);
        }
    }
    Ok(Ordering::Equal)
}

fn null_token(other: &VersionToken) -> VersionToken {
    VersionToken {
        prefix: other.prefix,
        value: if other.prefix == '.' { "0" } else { "" }.to_string(),
        is_null: true,
    }
}

fn compare_tokens(left: &VersionToken, right: &VersionToken) -> Ordering {
    if left.prefix != right.prefix {
        return qualifier_order(left).cmp(&qualifier_order(right));
    }
    let left_numeric = left.value.bytes().all(|byte| byte.is_ascii_digit());
    let right_numeric = right.value.bytes().all(|byte| byte.is_ascii_digit());
    match (left_numeric, right_numeric) {
        (true, true) => numeric_cmp(&left.value, &right.value),
        (true, false) if !left.is_null => Ordering::Greater,
        (false, true) if !right.is_null => Ordering::Less,
        _ => qualifier_cmp(&left.value, &right.value),
    }
}

fn qualifier_order(token: &VersionToken) -> u8 {
    match (
        token.prefix,
        token.value.bytes().all(|byte| byte.is_ascii_digit()),
    ) {
        ('.', false) => 0,
        ('-', false) => 1,
        ('-', true) => 2,
        ('.', true) => 3,
        _ => 0,
    }
}

fn numeric_cmp(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn qualifier_cmp(left: &str, right: &str) -> Ordering {
    const KEYWORDS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];
    let key = |value: &str| {
        KEYWORDS
            .iter()
            .position(|candidate| *candidate == value)
            .unwrap_or(KEYWORDS.len())
    };
    key(left).cmp(&key(right)).then_with(|| left.cmp(right))
}

#[derive(Debug, Error)]
pub enum MavenError {
    #[error("invalid Maven package name: {0}")]
    InvalidPackageName(String),
    #[error("invalid Maven coordinate: {0}")]
    InvalidCoordinate(String),
    #[error("invalid Maven version: {0}")]
    InvalidVersion(String),
    #[error("Maven version not found: {0}")]
    VersionNotFound(String),
    #[error("invalid Maven POM: {0}")]
    InvalidPom(String),
    #[error("{kind} exceeds the {limit}-byte limit")]
    BodyTooLarge { kind: &'static str, limit: usize },
    #[error("Maven POM body could not be read: {0}")]
    BodyRead(String),
    #[error("Maven POM is not valid UTF-8: {0}")]
    InvalidPomEncoding(String),
    #[error("Maven metadata is not valid UTF-8: {0}")]
    InvalidMetadataEncoding(String),
    #[error("invalid Maven metadata: {0}")]
    InvalidMetadata(String),
    #[error("invalid Maven metadata path: {0}")]
    InvalidMetadataPath(String),
    #[error("invalid Maven artifact path: {0}")]
    InvalidArtifactPath(String),
    #[error("Maven metadata not found: {0}")]
    MetadataNotFound(String),
    #[error("Maven artifact not found: {0}")]
    ArtifactNotFound(String),
    #[error("Maven metadata coordinate mismatch: expected {expected}, got {actual}")]
    MetadataCoordinateMismatch { expected: String, actual: String },
    #[error("Maven snapshots are unsupported: {0}")]
    SnapshotsUnsupported(String),
    #[error("Maven metadata route is unsupported by this provider")]
    UnsupportedMetadataRoute,
    #[error("Maven POM HEAD is unsupported by this provider")]
    UnsupportedPomHead,
    #[error("failed to enrich Maven version {version}: {message}")]
    VersionEnrichment { version: String, message: String },
    #[error("Maven package denied by policy")]
    Denied(Box<Decision>),
    #[error("Maven artifact delivery failed: {0}")]
    Delivery(#[from] ArtifactDeliveryError),
    #[error("Maven POM coordinate mismatch: expected {expected}, got {actual}")]
    CoordinateMismatch { expected: String, actual: String },
    #[error("Maven upstream request failed: {0}")]
    Request(#[from] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BlocklistEntry, MissingPublishTime};
    use crate::malicious::{MaliciousHit, OsvError};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    struct StaticProvider(MavenPomMetadata);

    #[async_trait]
    impl MavenMetadataProvider for StaticProvider {
        async fn fetch_pom(
            &self,
            _group_id: &str,
            _artifact_id: &str,
            _version: &str,
        ) -> Result<MavenPomMetadata, MavenError> {
            Ok(self.0.clone())
        }
    }

    struct StaticMetadataProvider {
        metadata: String,
        poms: HashMap<String, MavenPomMetadata>,
        current: AtomicUsize,
        maximum: AtomicUsize,
        delay: bool,
    }

    #[async_trait]
    impl MavenMetadataProvider for StaticMetadataProvider {
        async fn fetch_pom(
            &self,
            _group_id: &str,
            _artifact_id: &str,
            version: &str,
        ) -> Result<MavenPomMetadata, MavenError> {
            let current = self.current.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            self.maximum.fetch_max(current, AtomicOrdering::SeqCst);
            if self.delay {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            self.current.fetch_sub(1, AtomicOrdering::SeqCst);
            self.poms
                .get(version)
                .cloned()
                .ok_or_else(|| MavenError::VersionNotFound(format!("com.acme:demo@{version}")))
        }

        async fn fetch_metadata(
            &self,
            _relative_path: &str,
        ) -> Result<MavenRawMetadata, MavenError> {
            Ok(MavenRawMetadata {
                body: self.metadata.clone(),
            })
        }
    }

    struct BatchChecker(AtomicUsize);

    #[async_trait]
    impl MaliciousChecker for BatchChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, OsvError> {
            panic!("metadata filtering should use check_many")
        }

        async fn check_many(
            &self,
            artifacts: &[Artifact],
        ) -> Result<Vec<Vec<MaliciousHit>>, OsvError> {
            self.0.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(vec![Vec::new(); artifacts.len()])
        }
    }

    struct CleanChecker;

    #[async_trait]
    impl MaliciousChecker for CleanChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, OsvError> {
            Ok(Vec::new())
        }
    }

    struct CapturingChecker(Mutex<Option<Artifact>>);

    #[async_trait]
    impl MaliciousChecker for CapturingChecker {
        async fn check(&self, artifact: &Artifact) -> Result<Vec<MaliciousHit>, OsvError> {
            *self.0.lock().unwrap() = Some(artifact.clone());
            Ok(Vec::new())
        }
    }

    struct DeliveryProvider {
        pom: MavenPomMetadata,
        artifact_exists: bool,
        validations: AtomicUsize,
    }

    #[async_trait]
    impl MavenMetadataProvider for DeliveryProvider {
        async fn fetch_pom(
            &self,
            _group_id: &str,
            _artifact_id: &str,
            _version: &str,
        ) -> Result<MavenPomMetadata, MavenError> {
            Ok(self.pom.clone())
        }

        async fn fetch_pom_head(
            &self,
            _group_id: &str,
            _artifact_id: &str,
            _version: &str,
        ) -> Result<MavenPomHead, MavenError> {
            Ok(MavenPomHead {
                last_modified: self.pom.last_modified.clone(),
                sha256: self.pom.sha256.clone(),
                upstream_url: self.pom.upstream_url.clone(),
            })
        }

        async fn validate_artifact(&self, relative_path: &str) -> Result<(), MavenError> {
            self.validations.fetch_add(1, AtomicOrdering::SeqCst);
            if self.artifact_exists {
                Ok(())
            } else {
                Err(MavenError::ArtifactNotFound(relative_path.to_string()))
            }
        }
    }

    struct MaliciousBatchChecker(AtomicUsize);

    #[async_trait]
    impl MaliciousChecker for MaliciousBatchChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, OsvError> {
            panic!("metadata filtering should use check_many")
        }

        async fn check_many(
            &self,
            artifacts: &[Artifact],
        ) -> Result<Vec<Vec<MaliciousHit>>, OsvError> {
            self.0.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(artifacts
                .iter()
                .map(|artifact| {
                    (artifact.version == "4.0")
                        .then(|| {
                            vec![MaliciousHit {
                                osv_id: "MAL-2026-000001".to_string(),
                                summary: None,
                                source: "osv".to_string(),
                                modified: None,
                                effective_severity: None,
                                evaluation_error: None,
                            }]
                        })
                        .unwrap_or_default()
                })
                .collect())
        }
    }

    fn pom_metadata(version: &str) -> MavenPomMetadata {
        MavenPomMetadata {
            body: format!(
                "<project><groupId>com.acme</groupId><artifactId>demo</artifactId><version>{version}</version></project>"
            ),
            last_modified: Some("Sun, 01 Jun 2025 00:00:00 GMT".to_string()),
            sha256: None,
            upstream_url: format!("https://repo.example/demo/{version}/demo-{version}.pom"),
        }
    }

    fn metadata_xml(versions: &[String]) -> String {
        format!(
            "<metadata><groupId>com.acme</groupId><artifactId>demo</artifactId><versioning><latest>ignored</latest><release>ignored</release><versions>{}</versions><lastUpdated>20260711000000</lastUpdated></versioning></metadata>",
            versions
                .iter()
                .map(|version| format!("<version>{version}</version>"))
                .collect::<String>()
        )
    }

    #[test]
    fn parses_osv_package_name_without_losing_group_separator() {
        assert_eq!(
            parse_package_name("com.google.guava:guava").unwrap(),
            ("com.google.guava", "guava")
        );
        assert!(parse_package_name("guava").is_err());
        assert!(parse_package_name("a:b:c").is_err());
    }

    #[test]
    fn builds_standard_release_pom_url() {
        assert_eq!(
            pom_url(
                "https://repo.maven.apache.org/maven2/",
                "com.google.guava",
                "guava",
                "33.4.8-jre"
            ),
            "https://repo.maven.apache.org/maven2/com/google/guava/guava/33.4.8-jre/guava-33.4.8-jre.pom"
        );
    }

    #[test]
    fn compares_maven_qualifiers_and_numeric_transitions() {
        let ascending = [
            "1-alpha1",
            "1-beta1",
            "1-m1",
            "1-rc1",
            "1-snapshot",
            "1",
            "1-sp",
            "1.1",
        ];
        for pair in ascending.windows(2) {
            assert_eq!(compare_versions(pair[0], pair[1]).unwrap(), Ordering::Less);
        }
        assert_eq!(compare_versions("1.0", "1").unwrap(), Ordering::Equal);
        assert_eq!(compare_versions("1-ga", "1").unwrap(), Ordering::Equal);
        assert_eq!(compare_versions("1-cr1", "1-rc1").unwrap(), Ordering::Equal);
        assert_eq!(
            compare_versions("1.0.10", "1.0.2").unwrap(),
            Ordering::Greater
        );
    }

    #[test]
    fn matches_representative_osv_maven_comparator_cases() {
        for equal in [
            ["1", "1.0"],
            ["1", "1.0.0"],
            ["1", "1-ga"],
            ["1", "1-final"],
            ["1", "1-release"],
            ["1a1", "1-alpha-1"],
            ["1b2", "1-beta-2"],
            ["1m3", "1-milestone-3"],
            ["1cr", "1rc"],
            ["1.01", "1.1"],
        ] {
            assert_eq!(
                compare_versions(equal[0], equal[1]).unwrap(),
                Ordering::Equal,
                "expected {} == {}",
                equal[0],
                equal[1]
            );
        }
        for ordered in [
            ["1-alpha2", "1-beta1"],
            ["1-snapshot", "1"],
            ["1", "1-sp"],
            ["1-abc", "1-def"],
            ["1-foo", "1-1"],
            ["2-1", "2.0.a"],
            ["2.0.1-xyz", "2.0.1-123"],
            ["2.0-1", "2.0.1"],
            ["11.a2", "11.a11"],
            ["123456789012345.1", "12345678901234567890.1"],
        ] {
            assert_eq!(
                compare_versions(ordered[0], ordered[1]).unwrap(),
                Ordering::Less,
                "expected {} < {}",
                ordered[0],
                ordered[1]
            );
        }
        for invalid in ["", "1 2", "1/2"] {
            assert!(compare_versions(invalid, "1").is_err());
        }
    }

    #[test]
    fn rejects_oversized_declared_pom_length() {
        assert!(matches!(
            ensure_pom_content_length(Some(MAX_POM_BYTES as u64 + 1)),
            Err(MavenError::BodyTooLarge {
                kind: "POM",
                limit: MAX_POM_BYTES
            })
        ));
        ensure_pom_content_length(Some(MAX_POM_BYTES as u64)).unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_chunked_pom_body() {
        let chunks = futures_util::stream::iter([
            Ok::<_, &'static str>(vec![b'a'; MAX_POM_BYTES]),
            Ok(vec![b'b']),
        ]);
        assert!(matches!(
            collect_bounded_pom(chunks).await,
            Err(MavenError::BodyTooLarge {
                kind: "Maven POM",
                limit: MAX_POM_BYTES
            })
        ));
    }

    #[tokio::test]
    async fn lookup_validates_effective_coordinate_and_publish_time() {
        let provider = StaticProvider(MavenPomMetadata {
            body: r#"<project><modelVersion>4.0.0</modelVersion><groupId>com.acme</groupId><artifactId>demo</artifactId><version>1.2.3</version></project>"#.to_string(),
            last_modified: Some("Mon, 14 Apr 2025 17:25:22 GMT".to_string()),
            sha256: Some("abc123".to_string()),
            upstream_url: "https://repo.example/com/acme/demo/1.2.3/demo-1.2.3.pom".to_string(),
        });
        let artifact = lookup_artifact(&provider, "com.acme:demo", "1.2.3")
            .await
            .unwrap();
        assert_eq!(artifact.identity(), "maven:com.acme:demo@1.2.3");
        assert_eq!(
            artifact.published_at.unwrap().to_rfc3339(),
            "2025-04-14T17:25:22+00:00"
        );
        assert_eq!(artifact.hashes.sha256.as_deref(), Some("abc123"));
    }

    #[tokio::test]
    async fn lookup_accepts_inherited_group_and_version() {
        let provider = StaticProvider(MavenPomMetadata {
            body: r#"<project><parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.2.3</version></parent><artifactId>demo</artifactId></project>"#.to_string(),
            last_modified: None,
            sha256: None,
            upstream_url: "https://repo.example/demo.pom".to_string(),
        });
        lookup_artifact(&provider, "com.acme:demo", "1.2.3")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn malformed_publish_time_becomes_missing_policy_input() {
        let provider = StaticProvider(MavenPomMetadata {
            body: r#"<project><groupId>com.acme</groupId><artifactId>demo</artifactId><version>1.2.3</version></project>"#.to_string(),
            last_modified: Some("not-an-http-date".to_string()),
            sha256: None,
            upstream_url: "https://repo.example/demo.pom".to_string(),
        });
        let artifact = lookup_artifact(&provider, "com.acme:demo", "1.2.3")
            .await
            .unwrap();
        assert_eq!(artifact.published_at, None);
    }

    #[tokio::test]
    async fn metadata_filters_policy_denials_and_missing_versions_in_one_batch() {
        let mut config = Config::default();
        config.policy.missing_publish_time = MissingPublishTime::Allow;
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Maven,
            name: "com.acme:demo".to_string(),
            versions: vec!["2.0".to_string()],
            reason: "blocked fixture".to_string(),
        });
        let provider = StaticMetadataProvider {
            metadata: metadata_xml(&[
                "1.0".into(),
                "2.0".into(),
                "2.5".into(),
                "3.0".into(),
                "4.0".into(),
            ]),
            poms: HashMap::from([
                ("1.0".to_string(), pom_metadata("1.0")),
                ("2.0".to_string(), pom_metadata("2.0")),
                (
                    "2.5".to_string(),
                    MavenPomMetadata {
                        last_modified: Some("Fri, 10 Jul 2026 12:00:00 GMT".to_string()),
                        ..pom_metadata("2.5")
                    },
                ),
                ("4.0".to_string(), pom_metadata("4.0")),
            ]),
            current: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            delay: false,
        };
        let checker = MaliciousBatchChecker(AtomicUsize::new(0));

        let response = filtered_metadata_response(
            &config,
            &provider,
            &checker,
            "com.acme",
            "demo",
            DateTime::parse_from_rfc3339("2026-07-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .await
        .unwrap();
        let body = String::from_utf8(response.body.clone()).unwrap();
        assert!(body.contains("<latest>1.0</latest>"));
        assert!(body.contains("<release>1.0</release>"));
        assert!(body.contains("<version>1.0</version>"));
        assert!(!body.contains("<version>2.0</version>"));
        assert!(!body.contains("<version>2.5</version>"));
        assert!(!body.contains("<version>3.0</version>"));
        assert!(!body.contains("<version>4.0</version>"));
        assert_eq!(checker.0.load(AtomicOrdering::SeqCst), 1);

        let etag = response
            .headers
            .iter()
            .find(|(name, _)| name == "etag")
            .unwrap()
            .1
            .clone();
        let conditional = apply_if_none_match(response.clone(), Some(&etag));
        assert_eq!(conditional.status, 304);
        assert!(conditional.body.is_empty());
        for checksum in [
            MetadataChecksum::Md5,
            MetadataChecksum::Sha1,
            MetadataChecksum::Sha256,
            MetadataChecksum::Sha512,
        ] {
            let sidecar = checksum_response(&response, checksum);
            assert_eq!(sidecar.status, 200);
            assert!(sidecar.body.ends_with(b"\n"));
        }
    }

    #[tokio::test]
    async fn metadata_enrichment_never_exceeds_concurrency_bound() {
        let versions = (0..24)
            .map(|index| format!("1.0.{index}"))
            .collect::<Vec<_>>();
        let provider = StaticMetadataProvider {
            metadata: metadata_xml(&versions),
            poms: versions
                .iter()
                .map(|version| (version.clone(), pom_metadata(version)))
                .collect(),
            current: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            delay: true,
        };
        let mut config = Config::default();
        config.policy.minimum_age = Duration::ZERO;
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
        let checker = BatchChecker(AtomicUsize::new(0));

        filtered_metadata_response(&config, &provider, &checker, "com.acme", "demo", Utc::now())
            .await
            .unwrap();
        assert!(provider.maximum.load(AtomicOrdering::SeqCst) <= 16);
        assert!(provider.maximum.load(AtomicOrdering::SeqCst) > 1);
    }

    #[tokio::test]
    async fn metadata_rejects_coordinate_mismatch_and_snapshots() {
        let config = Config::default();
        let checker = BatchChecker(AtomicUsize::new(0));
        let mismatch = StaticMetadataProvider {
            metadata: "<metadata><groupId>other</groupId><artifactId>demo</artifactId><versioning><versions><version>1.0</version></versions></versioning></metadata>".to_string(),
            poms: HashMap::new(),
            current: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            delay: false,
        };
        assert!(matches!(
            filtered_metadata_response(
                &config,
                &mismatch,
                &checker,
                "com.acme",
                "demo",
                Utc::now()
            )
            .await,
            Err(MavenError::MetadataCoordinateMismatch { .. })
        ));

        let snapshot = StaticMetadataProvider {
            metadata: metadata_xml(&["1.0-SNAPSHOT".to_string()]),
            poms: HashMap::new(),
            current: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            delay: false,
        };
        assert!(matches!(
            filtered_metadata_response(
                &config,
                &snapshot,
                &checker,
                "com.acme",
                "demo",
                Utc::now()
            )
            .await,
            Err(MavenError::SnapshotsUnsupported(_))
        ));
    }

    #[tokio::test]
    async fn metadata_route_passes_group_plugin_metadata_and_owns_checksum() {
        let raw = "<metadata><plugins><plugin><name>Compiler</name><prefix>compiler</prefix><artifactId>maven-compiler-plugin</artifactId></plugin></plugins></metadata>";
        let provider = StaticMetadataProvider {
            metadata: raw.to_string(),
            poms: HashMap::new(),
            current: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            delay: false,
        };
        let response = metadata_route_response(
            &Config::default(),
            &provider,
            &BatchChecker(AtomicUsize::new(0)),
            "org/apache/maven/plugins/maven-metadata.xml",
            None,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(response.body, raw.as_bytes());

        let checksum = metadata_route_response(
            &Config::default(),
            &provider,
            &BatchChecker(AtomicUsize::new(0)),
            "org/apache/maven/plugins/maven-metadata.xml",
            Some(MetadataChecksum::Sha256),
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(
            String::from_utf8(checksum.body).unwrap(),
            format!("{}\n", hex_digest::<Sha256>(raw.as_bytes()))
        );
    }

    #[test]
    fn conditional_metadata_uses_weak_entity_tag_comparison() {
        let response = metadata_body_response(b"metadata".to_vec());
        let etag = response
            .headers
            .iter()
            .find(|(name, _)| name == "etag")
            .unwrap()
            .1
            .clone();
        assert_eq!(
            apply_if_none_match(response.clone(), Some(&format!("W/{etag}"))).status,
            304
        );
        assert_eq!(
            apply_if_none_match(response.clone(), Some(&format!("\"other\", W/{etag}"))).status,
            304
        );
        assert_eq!(
            apply_if_none_match(response, Some("W/\"other\"")).status,
            200
        );
    }

    #[test]
    fn conditional_metadata_wildcard_only_applies_to_existing_representation() {
        let response = metadata_body_response(b"metadata".to_vec());
        assert_eq!(apply_if_none_match(response, Some("*")).status, 304);

        for status in [404, 502] {
            let error =
                RegistryResponse::json(status, &serde_json::json!({"message": "upstream failure"}))
                    .unwrap();
            let preserved = apply_if_none_match(error.clone(), Some("*"));
            assert_eq!(preserved, error);
        }
    }

    #[tokio::test]
    async fn metadata_route_does_not_pass_through_malformed_artifact_metadata() {
        let provider = StaticMetadataProvider {
            metadata:
                "<metadata><groupId>com.acme</groupId><artifactId>demo</artifactId><versioning>"
                    .to_string(),
            poms: HashMap::new(),
            current: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            delay: false,
        };
        assert!(matches!(
            metadata_route_response(
                &Config::default(),
                &provider,
                &BatchChecker(AtomicUsize::new(0)),
                "com/acme/demo/maven-metadata.xml",
                None,
                Utc::now()
            )
            .await,
            Err(MavenError::InvalidMetadata(_))
        ));
    }

    #[test]
    fn parses_strict_release_paths_for_all_coordinate_scoped_files() {
        for path in [
            "com/acme/demo/1.2.3/demo-1.2.3.pom",
            "com/acme/demo/1.2.3/demo-1.2.3.jar",
            "com/acme/demo/1.2.3/demo-1.2.3.module",
            "com/acme/demo/1.2.3/demo-1.2.3-sources.jar",
            "com/acme/demo/1.2.3/demo-1.2.3-linux-x86_64.tar.gz",
            "com/acme/demo/1.2.3/demo-1.2.3.jar.sha256",
            "com/acme/demo/1.2.3/demo-1.2.3.pom.asc",
        ] {
            let route = parse_release_path(path).unwrap();
            assert_eq!(route.group_id, "com.acme");
            assert_eq!(route.artifact_id, "demo");
            assert_eq!(route.version, "1.2.3");
            assert_eq!(route.relative_path, path);
        }
        for invalid in [
            "com/acme/demo/1.2.3/other-1.2.3.jar",
            "com/acme/demo/1.2.3/demo-1.2.3",
            "com/acme/demo/1.2.3/demo-1.2.3-sources",
            "com/acme/demo/1.2.3/../secret.jar",
            "com/acme%2Fdemo/1.2.3/demo-1.2.3.jar",
            "com/acme/demo/1.2-SNAPSHOT/demo-1.2-SNAPSHOT.jar",
        ] {
            assert!(parse_release_path(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[tokio::test]
    async fn allowed_redirect_validates_exact_file_before_returning_location() {
        let mut config = Config::default();
        config.upstreams.maven.repository_url = "https://repo.example/maven2".to_string();
        let provider = DeliveryProvider {
            pom: pom_metadata("1.0"),
            artifact_exists: true,
            validations: AtomicUsize::new(0),
        };
        let route = parse_release_path("com/acme/demo/1.0/demo-1.0.jar").unwrap();
        let delivery = crate::artifacts::ArtifactDeliveryClient::new();
        let response = artifact_delivery_response(
            &config,
            &provider,
            &CleanChecker,
            &route,
            Utc::now(),
            ArtifactDeliveryOptions::new(&delivery),
        )
        .await
        .unwrap()
        .into_registry_response()
        .await;
        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            vec![(
                "location".to_string(),
                "https://repo.example/maven2/com/acme/demo/1.0/demo-1.0.jar".to_string()
            )]
        );
        assert_eq!(provider.validations.load(AtomicOrdering::SeqCst), 1);
    }

    #[tokio::test]
    async fn non_pom_delivery_never_inherits_pom_hash() {
        let mut config = Config::default();
        config.upstreams.maven.repository_url = "https://repo.example/maven2".to_string();
        let provider = DeliveryProvider {
            pom: MavenPomMetadata {
                sha256: Some("pom-digest".to_string()),
                ..pom_metadata("1.0")
            },
            artifact_exists: true,
            validations: AtomicUsize::new(0),
        };
        let checker = CapturingChecker(Mutex::new(None));
        let route = parse_release_path("com/acme/demo/1.0/demo-1.0.jar").unwrap();
        let delivery = crate::artifacts::ArtifactDeliveryClient::new();
        artifact_delivery_response(
            &config,
            &provider,
            &checker,
            &route,
            Utc::now(),
            ArtifactDeliveryOptions::new(&delivery),
        )
        .await
        .unwrap();
        let artifact = checker.0.lock().unwrap().clone().unwrap();
        assert_eq!(artifact.filename.as_deref(), Some("demo-1.0.jar"));
        assert_eq!(artifact.hashes, ArtifactHashes::default());
    }

    #[tokio::test]
    async fn missing_redirect_artifact_maps_to_404() {
        let config = Config::default();
        let provider = DeliveryProvider {
            pom: pom_metadata("1.0"),
            artifact_exists: false,
            validations: AtomicUsize::new(0),
        };
        let route = parse_release_path("com/acme/demo/1.0/demo-1.0.jar").unwrap();
        let delivery = crate::artifacts::ArtifactDeliveryClient::new();
        let error = match artifact_delivery_response(
            &config,
            &provider,
            &CleanChecker,
            &route,
            Utc::now(),
            ArtifactDeliveryOptions::new(&delivery),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("missing artifact should not be delivered"),
        };
        assert_eq!(error_response(&error).status, 404);
    }

    #[tokio::test]
    async fn blocked_proxy_artifact_never_contacts_byte_endpoint() {
        let (repository_url, request) = serve_artifact_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nbytes",
        )
        .await;
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        config.upstreams.maven.repository_url = repository_url;
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Maven,
            name: "com.acme:demo".to_string(),
            versions: vec!["1.0".to_string()],
            reason: "blocked fixture".to_string(),
        });
        let provider = DeliveryProvider {
            pom: pom_metadata("1.0"),
            artifact_exists: true,
            validations: AtomicUsize::new(0),
        };
        let route = parse_release_path("com/acme/demo/1.0/demo-1.0.jar").unwrap();
        let delivery = crate::artifacts::ArtifactDeliveryClient::new();
        let error = match artifact_delivery_response(
            &config,
            &provider,
            &CleanChecker,
            &route,
            Utc::now(),
            ArtifactDeliveryOptions::new(&delivery),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("blocked artifact should not be delivered"),
        };
        let response = error_response(&error);
        assert_eq!(response.status, 403);
        let decision: Decision = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(decision.package, "maven:com.acme:demo@1.0");
        assert!(timeout(Duration::from_millis(100), request).await.is_err());
    }

    #[tokio::test]
    async fn allowed_proxy_preserves_exact_artifact_bytes() {
        let (repository_url, request) = serve_artifact_once(
            "HTTP/1.1 200 OK\r\ncontent-type: application/java-archive\r\ncontent-length: 5\r\nconnection: close\r\n\r\nbytes",
        )
        .await;
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        config.upstreams.maven.repository_url = repository_url;
        let provider = DeliveryProvider {
            pom: pom_metadata("1.0"),
            artifact_exists: true,
            validations: AtomicUsize::new(0),
        };
        let route = parse_release_path("com/acme/demo/1.0/demo-1.0.jar").unwrap();
        let delivery = crate::artifacts::ArtifactDeliveryClient::new();
        let response = artifact_delivery_response(
            &config,
            &provider,
            &CleanChecker,
            &route,
            Utc::now(),
            ArtifactDeliveryOptions::new(&delivery),
        )
        .await
        .unwrap()
        .into_registry_response()
        .await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"bytes");
        assert!(
            request
                .await
                .unwrap()
                .starts_with("get /com/acme/demo/1.0/demo-1.0.jar ")
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
        (format!("http://{address}"), handle)
    }
}
