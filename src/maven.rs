//! Maven Repository Layout metadata, identity, and version semantics.

use crate::artifact::{Artifact, ArtifactHashes, Ecosystem};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{Stream, StreamExt};
use quick_xml::de::from_str;
use reqwest::{Client, StatusCode, header};
use serde::Deserialize;
use std::cmp::Ordering;
use std::fmt::Display;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_POM_BYTES: usize = 1024 * 1024;

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

#[async_trait]
pub trait MavenMetadataProvider: Send + Sync {
    async fn fetch_pom(
        &self,
        group_id: &str,
        artifact_id: &str,
        version: &str,
    ) -> Result<MavenPomMetadata, MavenError>;
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
    if content_length.is_some_and(|length| length > MAX_POM_BYTES as u64) {
        return Err(MavenError::PomTooLarge(MAX_POM_BYTES));
    }
    Ok(())
}

async fn collect_bounded_pom<S, T, E>(mut stream: S) -> Result<Vec<u8>, MavenError>
where
    S: Stream<Item = Result<T, E>> + Unpin,
    T: AsRef<[u8]>,
    E: Display,
{
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| MavenError::BodyRead(error.to_string()))?;
        if body.len().saturating_add(chunk.as_ref().len()) > MAX_POM_BYTES {
            return Err(MavenError::PomTooLarge(MAX_POM_BYTES));
        }
        body.extend_from_slice(chunk.as_ref());
    }
    Ok(body)
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
    #[error("Maven POM exceeds the {0}-byte limit")]
    PomTooLarge(usize),
    #[error("Maven POM body could not be read: {0}")]
    BodyRead(String),
    #[error("Maven POM is not valid UTF-8: {0}")]
    InvalidPomEncoding(String),
    #[error("Maven POM coordinate mismatch: expected {expected}, got {actual}")]
    CoordinateMismatch { expected: String, actual: String },
    #[error("Maven upstream request failed: {0}")]
    Request(#[from] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

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
            Err(MavenError::PomTooLarge(MAX_POM_BYTES))
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
            Err(MavenError::PomTooLarge(MAX_POM_BYTES))
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
}
