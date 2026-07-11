//! RubyGems registry metadata and version semantics.
//!
//! Protocol-specific identity, platform, and `Gem::Version` behavior stays in
//! this adapter so the shared policy engine remains ecosystem-neutral.

use crate::artifact::{Artifact, ArtifactHashes, Ecosystem};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct RubyGemsClient {
    registry_url: String,
    client: Client,
}

impl RubyGemsClient {
    pub fn new(registry_url: impl Into<String>) -> Self {
        Self {
            registry_url: registry_url.into().trim_end_matches('/').to_string(),
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("RubyGems HTTP client should build"),
        }
    }

    fn versions_url(&self, name: &str) -> Result<Url, RubyGemsError> {
        validate_name(name)?;
        let mut url = Url::parse(&self.registry_url)
            .map_err(|error| RubyGemsError::InvalidMetadata(error.to_string()))?;
        url.path_segments_mut()
            .map_err(|_| {
                RubyGemsError::InvalidMetadata("registry URL cannot be a base URL".into())
            })?
            .extend(["api", "v1", "versions", &format!("{name}.json")]);
        Ok(url)
    }
}

#[async_trait]
pub trait RubyGemsProvider: Send + Sync {
    async fn fetch_versions(&self, name: &str) -> Result<Vec<GemVersion>, RubyGemsError>;
}

#[async_trait]
impl RubyGemsProvider for RubyGemsClient {
    async fn fetch_versions(&self, name: &str) -> Result<Vec<GemVersion>, RubyGemsError> {
        Ok(self
            .client
            .get(self.versions_url(name)?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct GemVersion {
    pub number: String,
    pub platform: String,
    pub created_at: DateTime<Utc>,
    pub sha: String,
    #[serde(default)]
    pub yanked: bool,
    pub gem_uri: String,
}

impl GemVersion {
    pub fn filename(&self, name: &str) -> String {
        if self.platform == "ruby" {
            format!("{name}-{}.gem", self.number)
        } else {
            format!("{name}-{}-{}.gem", self.number, self.platform)
        }
    }

    pub fn artifact(&self, name: &str) -> Result<Artifact, RubyGemsError> {
        validate_name(name)?;
        RubyGemsVersion::parse(&self.number)?;
        validate_platform(&self.platform)?;
        validate_sha256(&self.sha)?;
        let filename = self.filename(name);
        let upstream = Url::parse(&self.gem_uri)
            .map_err(|error| RubyGemsError::InvalidMetadata(error.to_string()))?;
        if upstream.path_segments().and_then(Iterator::last) != Some(filename.as_str()) {
            return Err(RubyGemsError::InvalidMetadata(format!(
                "gem URI does not match canonical filename {filename}"
            )));
        }
        Ok(Artifact {
            ecosystem: Ecosystem::RubyGems,
            name: name.to_string(),
            version: self.number.clone(),
            filename: Some(filename),
            upstream_url: Some(self.gem_uri.clone()),
            published_at: Some(self.created_at),
            hashes: ArtifactHashes {
                sha256: Some(self.sha.to_ascii_lowercase()),
                ..ArtifactHashes::default()
            },
        })
    }
}

pub async fn lookup_artifacts(
    provider: &dyn RubyGemsProvider,
    name: &str,
    version: &str,
) -> Result<Vec<Artifact>, RubyGemsError> {
    validate_name(name)?;
    let requested = RubyGemsVersion::parse(version)?;
    let mut artifacts = provider
        .fetch_versions(name)
        .await?
        .into_iter()
        .filter(|candidate| !candidate.yanked)
        .map(|candidate| {
            RubyGemsVersion::parse(&candidate.number).map(|parsed| (candidate, parsed))
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|(candidate, parsed)| {
            (parsed.cmp(&requested) == Ordering::Equal).then_some(candidate)
        })
        .map(|candidate| candidate.artifact(name))
        .collect::<Result<Vec<_>, _>>()?;
    artifacts.sort_by(|left, right| left.filename.cmp(&right.filename));
    if artifacts.is_empty() {
        return Err(RubyGemsError::VersionNotFound {
            name: name.to_string(),
            version: version.to_string(),
        });
    }
    Ok(artifacts)
}

pub fn validate_name(name: &str) -> Result<(), RubyGemsError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !name.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err(RubyGemsError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn validate_platform(platform: &str) -> Result<(), RubyGemsError> {
    if platform.is_empty()
        || platform.len() > 128
        || !platform
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RubyGemsError::InvalidMetadata(format!(
            "invalid RubyGems platform {platform}"
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), RubyGemsError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RubyGemsError::InvalidMetadata(
            "gem SHA-256 must contain 64 hexadecimal characters".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubyGemsVersion {
    segments: Vec<VersionSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VersionSegment {
    Numeric(String),
    Alpha(String),
}

impl RubyGemsVersion {
    pub fn parse(value: &str) -> Result<Self, RubyGemsError> {
        let value = value.trim();
        if value.is_empty() || !valid_version_grammar(value) {
            return Err(RubyGemsError::InvalidVersion(value.to_string()));
        }
        let expanded = value.replace('-', ".pre.");
        let mut segments = Vec::new();
        let bytes = expanded.as_bytes();
        let mut start = 0;
        while start < bytes.len() {
            if !bytes[start].is_ascii_alphanumeric() {
                start += 1;
                continue;
            }
            let numeric = bytes[start].is_ascii_digit();
            let mut end = start + 1;
            while end < bytes.len()
                && bytes[end].is_ascii_alphanumeric()
                && bytes[end].is_ascii_digit() == numeric
            {
                end += 1;
            }
            let part = &expanded[start..end];
            segments.push(if numeric {
                VersionSegment::Numeric(part.trim_start_matches('0').to_string())
            } else {
                VersionSegment::Alpha(part.to_ascii_lowercase())
            });
            start = end;
        }
        canonicalize(&mut segments);
        Ok(Self { segments })
    }
}

fn valid_version_grammar(value: &str) -> bool {
    let (release, prerelease) = value
        .split_once('-')
        .map_or((value, None), |(release, prerelease)| {
            (release, Some(prerelease))
        });
    let mut release_parts = release.split('.');
    let Some(first) = release_parts.next() else {
        return false;
    };
    if first.is_empty() || !first.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if release_parts
        .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    {
        return false;
    }
    prerelease.is_none_or(|suffix| {
        !suffix.is_empty()
            && suffix.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
    })
}

fn canonicalize(segments: &mut Vec<VersionSegment>) {
    while matches!(segments.last(), Some(VersionSegment::Numeric(value)) if value.is_empty()) {
        segments.pop();
    }
    if let Some(first_alpha) = segments
        .iter()
        .position(|segment| matches!(segment, VersionSegment::Alpha(_)))
    {
        let mut index = first_alpha;
        while index > 0
            && matches!(&segments[index - 1], VersionSegment::Numeric(value) if value.is_empty())
        {
            segments.remove(index - 1);
            index -= 1;
        }
    }
}

impl Ord for RubyGemsVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let limit = self.segments.len().min(other.segments.len());
        for index in 0..limit {
            let ordering = match (&self.segments[index], &other.segments[index]) {
                (VersionSegment::Numeric(left), VersionSegment::Numeric(right)) => {
                    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
                }
                (VersionSegment::Alpha(left), VersionSegment::Alpha(right)) => left.cmp(right),
                (VersionSegment::Alpha(_), VersionSegment::Numeric(_)) => Ordering::Less,
                (VersionSegment::Numeric(_), VersionSegment::Alpha(_)) => Ordering::Greater,
            };
            if ordering != Ordering::Equal {
                return ordering;
            }
        }
        compare_remaining(&self.segments[limit..], &other.segments[limit..])
    }
}

impl PartialOrd for RubyGemsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_remaining(left: &[VersionSegment], right: &[VersionSegment]) -> Ordering {
    if left.is_empty() {
        for segment in right {
            match segment {
                VersionSegment::Alpha(_) => return Ordering::Greater,
                VersionSegment::Numeric(value) if !value.is_empty() => return Ordering::Less,
                _ => {}
            }
        }
        Ordering::Equal
    } else {
        compare_remaining(right, left).reverse()
    }
}

pub fn compare_versions(left: &str, right: &str) -> Result<Ordering, RubyGemsError> {
    Ok(RubyGemsVersion::parse(left)?.cmp(&RubyGemsVersion::parse(right)?))
}

#[derive(Debug, Error)]
pub enum RubyGemsError {
    #[error("RubyGems upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("invalid RubyGems name: {0}")]
    InvalidName(String),
    #[error("invalid RubyGems version: {0}")]
    InvalidVersion(String),
    #[error("invalid RubyGems metadata: {0}")]
    InvalidMetadata(String),
    #[error("RubyGems version not found: {name}@{version}")]
    VersionNotFound { name: String, version: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn gem(number: &str, platform: &str, yanked: bool) -> GemVersion {
        let suffix = if platform == "ruby" {
            format!("demo-{number}.gem")
        } else {
            format!("demo-{number}-{platform}.gem")
        };
        GemVersion {
            number: number.into(),
            platform: platform.into(),
            created_at: "2026-01-01T00:00:00Z".parse().unwrap(),
            sha: "a".repeat(64),
            yanked,
            gem_uri: format!("https://rubygems.example/gems/{suffix}"),
        }
    }

    struct StaticProvider(HashMap<String, Vec<GemVersion>>);

    #[async_trait]
    impl RubyGemsProvider for StaticProvider {
        async fn fetch_versions(&self, name: &str) -> Result<Vec<GemVersion>, RubyGemsError> {
            Ok(self.0.get(name).cloned().unwrap_or_default())
        }
    }

    #[test]
    fn version_order_matches_representative_gem_version_cases() {
        let ordered = [
            "1.0.0.a",
            "1.0.0.a.1",
            "1.0.0.b1",
            "1.0.0-alpha",
            "1.0.0.rc1",
            "1.0.0",
            "1.0.1",
            "1.1",
            "2.0",
        ];
        for pair in ordered.windows(2) {
            assert_eq!(compare_versions(pair[0], pair[1]).unwrap(), Ordering::Less);
        }
        for (left, right) in [("1", "1.0.0"), ("1.0.a", "1.a"), ("1.0", "1.0.0")] {
            assert_eq!(compare_versions(left, right).unwrap(), Ordering::Equal);
        }
        assert_eq!(
            compare_versions("1.0-1", "1.0.a").unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions(
                "999999999999999999999999999999",
                "1000000000000000000000000000000"
            )
            .unwrap(),
            Ordering::Less
        );
    }

    #[tokio::test]
    async fn lookup_returns_each_non_yanked_platform_variant() {
        let provider = StaticProvider(HashMap::from([(
            "demo".into(),
            vec![
                gem("1.0.0", "ruby", false),
                gem("1.0", "arm64-darwin", false),
                gem("1.0.0", "java", true),
                gem("2.0.0", "ruby", false),
            ],
        )]));
        let artifacts = lookup_artifacts(&provider, "demo", "1.0.0").await.unwrap();
        assert_eq!(artifacts.len(), 2);
        assert_eq!(
            artifacts
                .iter()
                .map(|artifact| artifact.filename.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["demo-1.0-arm64-darwin.gem", "demo-1.0.0.gem"]
        );
        assert!(
            artifacts
                .iter()
                .all(|artifact| artifact.hashes.sha256.is_some())
        );
    }

    #[test]
    fn artifact_rejects_noncanonical_uri_and_hash() {
        let mut metadata = gem("1.0.0", "ruby", false);
        metadata.gem_uri = "https://rubygems.example/gems/other.gem".into();
        assert!(metadata.artifact("demo").is_err());
        metadata.gem_uri = "https://rubygems.example/gems/demo-1.0.0.gem".into();
        metadata.sha = "bad".into();
        assert!(metadata.artifact("demo").is_err());
    }

    #[test]
    fn validation_matches_rubygems_separator_and_name_boundaries() {
        for accepted in ["1", "1.0.a", "1-1", "1--1", "1.pre-1"] {
            RubyGemsVersion::parse(accepted).unwrap();
        }
        for rejected in ["1.-1", "1-.1", "1..1", "1-", "a.1"] {
            assert!(RubyGemsVersion::parse(rejected).is_err(), "{rejected}");
        }
        for accepted in ["demo", "demo-", "demo_", "demo."] {
            validate_name(accepted).unwrap();
        }
        for rejected in ["", "-demo", "_demo", ".demo", "demo/path"] {
            assert!(validate_name(rejected).is_err(), "{rejected}");
        }
    }

    #[tokio::test]
    async fn lookup_fails_closed_on_malformed_upstream_versions() {
        let provider = StaticProvider(HashMap::from([(
            "demo".into(),
            vec![gem("1.-1", "ruby", false), gem("1.0.0", "ruby", false)],
        )]));
        assert!(lookup_artifacts(&provider, "demo", "1.0.0").await.is_err());
    }
}
