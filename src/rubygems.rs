//! RubyGems registry metadata and version semantics.
//!
//! Protocol-specific identity, platform, and `Gem::Version` behavior stays in
//! this adapter so the shared policy engine remains ecosystem-neutral.

use crate::artifact::{Artifact, ArtifactHashes, Ecosystem};
use crate::artifacts::{
    self, ArtifactDeliveryError, ArtifactDeliveryOptions, ArtifactDeliveryResponse,
};
use crate::config::Config;
use crate::http_body::{self, HttpBodyError};
use crate::malicious::MaliciousChecker;
use crate::policy::{Decision, PolicyEngine};
use crate::response::RegistryResponse;
use async_trait::async_trait;
use axum::http::{HeaderMap, header};
use base64::Engine;
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_GEM_VARIANTS: usize = 10_000;
const MAX_GEM_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_VERSIONS_INDEX_BYTES: usize = 64 * 1024 * 1024;
const MAX_COMPACT_INFO_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMPACT_INFO_LINES: usize = 100_000;
const MAX_ARTIFACT_FILENAME_BYTES: usize = 512;
const MAX_ARTIFACT_NAME_CANDIDATES: usize = 32;
const ARTIFACT_RESOLUTION_CONCURRENCY: usize = 8;
const COMPACT_CONTENT_TYPE: &str = "text/plain; charset=utf-8";

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
        let response = self
            .client
            .get(self.versions_url(name)?)
            .send()
            .await?
            .error_for_status()?;
        let mut versions: Vec<GemVersion> = http_body::collect_json(
            response,
            MAX_GEM_METADATA_BYTES,
            "RubyGems version metadata",
        )
        .await?;
        if versions.len() > MAX_GEM_VARIANTS {
            return Err(RubyGemsError::TooManyVariants(versions.len()));
        }
        for version in &mut versions {
            version.gem_uri = format!("{}/downloads/{}", self.registry_url, version.filename(name));
        }
        Ok(versions)
    }
}

#[async_trait]
pub trait CompactIndexProvider: Send + Sync {
    async fn fetch_versions_index(
        &self,
        request_headers: Option<&HeaderMap>,
    ) -> Result<RegistryResponse, RubyGemsError>;
    async fn fetch_info(&self, name: &str) -> Result<Vec<u8>, RubyGemsError>;
}

#[async_trait]
impl CompactIndexProvider for RubyGemsClient {
    async fn fetch_versions_index(
        &self,
        request_headers: Option<&HeaderMap>,
    ) -> Result<RegistryResponse, RubyGemsError> {
        let mut request = self.client.get(format!("{}/versions", self.registry_url));
        if let Some(headers) = request_headers {
            for name in [
                header::RANGE,
                header::IF_NONE_MATCH,
                header::IF_MODIFIED_SINCE,
                header::IF_RANGE,
            ] {
                if let Some(value) = headers.get(&name) {
                    request = request.header(name, value);
                }
            }
        }
        let response = request.send().await?;
        let status = response.status().as_u16();
        if status >= 400 {
            return Err(RubyGemsError::UpstreamStatus(status));
        }
        let headers = response
            .headers()
            .iter()
            .filter(|(name, _)| {
                matches!(
                    name.as_str(),
                    "content-type"
                        | "content-length"
                        | "etag"
                        | "last-modified"
                        | "accept-ranges"
                        | "content-range"
                        | "cache-control"
                        | "digest"
                        | "repr-digest"
                )
            })
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect();
        let body = http_body::collect_bytes(
            response,
            MAX_VERSIONS_INDEX_BYTES,
            "RubyGems versions index",
        )
        .await?;
        Ok(RegistryResponse {
            status,
            headers,
            body,
        })
    }

    async fn fetch_info(&self, name: &str) -> Result<Vec<u8>, RubyGemsError> {
        validate_name(name)?;
        let response = self
            .client
            .get(format!("{}/info/{name}", self.registry_url))
            .send()
            .await?;
        let status = response.status().as_u16();
        if status >= 400 {
            return Err(RubyGemsError::UpstreamStatus(status));
        }
        http_body::collect_bytes(response, MAX_COMPACT_INFO_BYTES, "RubyGems compact info")
            .await
            .map_err(RubyGemsError::from)
    }
}

pub async fn compact_info_response(
    config: &Config,
    metadata: &dyn RubyGemsProvider,
    compact: &dyn CompactIndexProvider,
    checker: &dyn MaliciousChecker,
    name: &str,
    now: DateTime<Utc>,
    request_headers: &HeaderMap,
) -> Result<RegistryResponse, RubyGemsError> {
    validate_name(name)?;
    let (raw, versions) =
        tokio::try_join!(compact.fetch_info(name), metadata.fetch_versions(name))?;
    let filtered = filter_compact_info(config, checker, name, &raw, versions, now).await?;
    Ok(filtered_representation_response(filtered, request_headers))
}

async fn filter_compact_info(
    config: &Config,
    checker: &dyn MaliciousChecker,
    name: &str,
    raw: &[u8],
    versions: Vec<GemVersion>,
    now: DateTime<Utc>,
) -> Result<Vec<u8>, RubyGemsError> {
    let raw = std::str::from_utf8(raw)
        .map_err(|_| RubyGemsError::InvalidMetadata("compact info must be UTF-8".into()))?;
    if raw.lines().count() > MAX_COMPACT_INFO_LINES {
        return Err(RubyGemsError::CompactInfoTooLarge);
    }
    let separator = raw
        .lines()
        .position(|line| line == "---")
        .ok_or_else(|| RubyGemsError::InvalidMetadata("compact info has no separator".into()))?;
    let mut metadata_by_key = BTreeMap::new();
    for version in versions {
        if version.yanked {
            continue;
        }
        let key = version.compact_key();
        if metadata_by_key.insert(key.clone(), version).is_some() {
            return Err(RubyGemsError::InvalidMetadata(format!(
                "duplicate RubyGems variant {key}"
            )));
        }
    }
    let lines = raw.lines().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();
    for line in lines
        .iter()
        .skip(separator + 1)
        .filter(|line| !line.is_empty())
    {
        let key = line.split_once(' ').map(|(key, _)| key).ok_or_else(|| {
            RubyGemsError::InvalidMetadata("compact info line has no version separator".into())
        })?;
        if !seen.insert(key.to_string()) {
            return Err(RubyGemsError::InvalidMetadata(format!(
                "duplicate compact info variant {key}"
            )));
        }
        let metadata = metadata_by_key.remove(key).ok_or_else(|| {
            RubyGemsError::InvalidMetadata(format!(
                "compact info variant {key} has no exact upstream metadata"
            ))
        })?;
        validate_compact_attributes(line, &metadata)?;
        candidates.push(((*line).to_string(), metadata.artifact(name)?));
    }
    if !metadata_by_key.is_empty() {
        return Err(RubyGemsError::InvalidMetadata(
            "upstream version metadata contains variants absent from compact info".into(),
        ));
    }
    let artifacts = candidates
        .iter()
        .map(|(_, artifact)| artifact.clone())
        .collect::<Vec<_>>();
    let decisions = evaluate_artifacts(config, checker, &artifacts, now).await;
    let mut output = lines[..=separator].join("\n");
    output.push('\n');
    for ((line, _), decision) in candidates.into_iter().zip(decisions) {
        if decision.allowed {
            output.push_str(&line);
            output.push('\n');
        }
    }
    Ok(output.into_bytes())
}

fn validate_compact_attributes(line: &str, metadata: &GemVersion) -> Result<(), RubyGemsError> {
    let attributes = line
        .rsplit_once('|')
        .map(|(_, value)| value)
        .ok_or_else(|| {
            RubyGemsError::InvalidMetadata("compact info line has no attributes".into())
        })?;
    let mut checksum = None;
    let mut created_at = None;
    for attribute in attributes.split(',') {
        if let Some(value) = attribute.strip_prefix("checksum:")
            && checksum.replace(value).is_some()
        {
            return Err(RubyGemsError::InvalidMetadata(
                "compact info has duplicate checksum".into(),
            ));
        }
        if let Some(value) = attribute.strip_prefix("created_at:")
            && created_at.replace(value).is_some()
        {
            return Err(RubyGemsError::InvalidMetadata(
                "compact info has duplicate created_at".into(),
            ));
        }
    }
    let checksum = checksum
        .ok_or_else(|| RubyGemsError::InvalidMetadata("compact info has no checksum".into()))?;
    if !checksum.eq_ignore_ascii_case(&metadata.sha) {
        return Err(RubyGemsError::InvalidMetadata(
            "compact info checksum disagrees with version metadata".into(),
        ));
    }
    let created_at = created_at
        .ok_or_else(|| RubyGemsError::InvalidMetadata("compact info has no created_at".into()))?
        .parse::<DateTime<Utc>>()
        .map_err(|error| RubyGemsError::InvalidMetadata(error.to_string()))?;
    if created_at.timestamp() != metadata.created_at.timestamp() {
        return Err(RubyGemsError::InvalidMetadata(
            "compact info created_at disagrees with version metadata".into(),
        ));
    }
    Ok(())
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
                "OSV batch returned {} results for {} RubyGems artifacts",
                results.len(),
                checked.len()
            )),
            Err(error) => Err(error.to_string()),
        }
    };
    let mut results_by_index = vec![None; artifacts.len()];
    for (batch_index, (artifact_index, artifact)) in indexed.iter().enumerate() {
        results_by_index[*artifact_index] = Some(match &results {
            Ok(results) => results
                .get(batch_index)
                .cloned()
                .ok_or_else(|| format!("OSV batch result missing for {}", artifact.identity())),
            Err(error) => Err(error.clone()),
        });
    }
    artifacts
        .iter()
        .zip(results_by_index)
        .map(|(artifact, result)| policy.evaluate_with_malicious_result(artifact, now, result))
        .collect()
}

fn filtered_representation_response(body: Vec<u8>, headers: &HeaderMap) -> RegistryResponse {
    let digest = Sha256::digest(&body);
    let etag = format!("\"{:x}\"", md5::compute(&body));
    let repr_digest = format!(
        "sha-256=\"{}\"",
        base64::engine::general_purpose::STANDARD.encode(digest)
    );
    let base_headers = || {
        vec![
            ("content-type".into(), COMPACT_CONTENT_TYPE.into()),
            ("etag".into(), etag.clone()),
            ("repr-digest".into(), repr_digest.clone()),
            ("digest".into(), repr_digest.clone()),
            ("accept-ranges".into(), "bytes".into()),
            ("cache-control".into(), "no-cache".into()),
        ]
    };
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| etag_list_matches(value, &etag))
    {
        return RegistryResponse {
            status: 304,
            headers: base_headers(),
            body: Vec::new(),
        };
    }
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let if_range_matches = headers
        .get(header::IF_RANGE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value.trim() == etag);
    if let Some(range) = range.filter(|_| if_range_matches) {
        match parse_range(range, body.len()) {
            Some((start, end)) => {
                let partial = body[start..=end].to_vec();
                let mut response_headers = base_headers();
                response_headers.push((
                    "content-range".into(),
                    format!("bytes {start}-{end}/{}", body.len()),
                ));
                response_headers.push(("content-length".into(), partial.len().to_string()));
                return RegistryResponse {
                    status: 206,
                    headers: response_headers,
                    body: partial,
                };
            }
            None => {
                let mut response_headers = base_headers();
                response_headers.push(("content-range".into(), format!("bytes */{}", body.len())));
                return RegistryResponse {
                    status: 416,
                    headers: response_headers,
                    body: Vec::new(),
                };
            }
        }
    }
    let mut response_headers = base_headers();
    response_headers.push(("content-length".into(), body.len().to_string()));
    RegistryResponse {
        status: 200,
        headers: response_headers,
        body,
    }
}

fn etag_list_matches(value: &str, etag: &str) -> bool {
    value.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate == etag || candidate.strip_prefix("W/") == Some(etag)
    })
}

fn parse_range(value: &str, length: usize) -> Option<(usize, usize)> {
    let range = value.strip_prefix("bytes=")?;
    if range.contains(',') || length == 0 {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<usize>().ok()?.min(length);
        return (suffix > 0).then_some((length - suffix, length - 1));
    }
    let start = start.parse::<usize>().ok()?;
    if start >= length {
        return None;
    }
    let end = if end.is_empty() {
        length - 1
    } else {
        end.parse::<usize>().ok()?.min(length - 1)
    };
    (start <= end).then_some((start, end))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct GemVersion {
    pub number: String,
    pub platform: String,
    pub created_at: DateTime<Utc>,
    pub sha: String,
    #[serde(default)]
    pub yanked: bool,
    #[serde(default)]
    pub gem_uri: String,
}

impl GemVersion {
    pub fn compact_key(&self) -> String {
        if self.platform == "ruby" {
            self.number.clone()
        } else {
            format!("{}-{}", self.number, self.platform)
        }
    }

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

pub async fn resolve_artifact(
    provider: &dyn RubyGemsProvider,
    filename: &str,
) -> Result<Artifact, RubyGemsError> {
    let stem = filename
        .strip_suffix(".gem")
        .filter(|stem| !stem.is_empty() && filename.len() <= MAX_ARTIFACT_FILENAME_BYTES)
        .ok_or_else(|| RubyGemsError::ArtifactNotFound(filename.to_string()))?;
    let candidates = stem
        .char_indices()
        .filter(|(_, character)| *character == '-')
        .map(|(index, _)| &stem[..index])
        .filter(|name| validate_name(name).is_ok())
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if candidates.is_empty() {
        return Err(RubyGemsError::ArtifactNotFound(filename.to_string()));
    }
    if candidates.len() > MAX_ARTIFACT_NAME_CANDIDATES {
        return Err(RubyGemsError::TooManyArtifactCandidates(candidates.len()));
    }
    let results = stream::iter(candidates)
        .map(|name| async move {
            let result = provider.fetch_versions(&name).await;
            (name, result)
        })
        .buffer_unordered(ARTIFACT_RESOLUTION_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut matches = Vec::new();
    for (name, result) in results {
        let versions = match result {
            Ok(versions) => versions,
            Err(error) if error.is_not_found() => continue,
            Err(error) => return Err(error),
        };
        for version in versions.into_iter().filter(|version| !version.yanked) {
            if version.filename(&name) == filename {
                matches.push(version.artifact(&name)?);
            }
        }
    }
    match matches.len() {
        0 => Err(RubyGemsError::ArtifactNotFound(filename.to_string())),
        1 => Ok(matches.pop().expect("one RubyGems artifact match")),
        count => Err(RubyGemsError::AmbiguousArtifact {
            filename: filename.to_string(),
            count,
        }),
    }
}

pub async fn artifact_delivery_response(
    config: &Config,
    provider: &dyn RubyGemsProvider,
    checker: &dyn MaliciousChecker,
    filename: &str,
    now: DateTime<Utc>,
    delivery: ArtifactDeliveryOptions<'_>,
) -> Result<ArtifactDeliveryResponse, RubyGemsError> {
    let artifact = resolve_artifact(provider, filename).await?;
    let decision = PolicyEngine::new(config)
        .evaluate(&artifact, now, checker)
        .await;
    if !decision.allowed {
        return Ok(ArtifactDeliveryResponse::Buffered(RegistryResponse::json(
            403,
            &serde_json::to_value(decision)?,
        )?));
    }
    let upstream = artifact
        .upstream_url
        .ok_or_else(|| RubyGemsError::InvalidMetadata("resolved gem has no upstream URL".into()))?;
    delivery
        .client
        .deliver(config, upstream, delivery.request_headers)
        .await
        .map_err(RubyGemsError::ArtifactDelivery)
}

pub fn error_response(error: &RubyGemsError) -> RegistryResponse {
    if let RubyGemsError::ArtifactDelivery(error) = error {
        return artifacts::gateway_error_response(error);
    }
    let status = if error.is_not_found() {
        404
    } else {
        match error {
            RubyGemsError::InvalidName(_)
            | RubyGemsError::InvalidVersion(_)
            | RubyGemsError::VersionNotFound { .. }
            | RubyGemsError::ArtifactNotFound(_) => 404,
            _ => 502,
        }
    };
    RegistryResponse::json(
        status,
        &serde_json::json!({
            "allowed": false,
            "reason": "rubygems_upstream_error",
            "message": error.to_string()
        }),
    )
    .expect("static RubyGems error response")
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
    #[error("RubyGems upstream body failed validation: {0}")]
    Body(#[from] HttpBodyError),
    #[error("invalid RubyGems name: {0}")]
    InvalidName(String),
    #[error("invalid RubyGems version: {0}")]
    InvalidVersion(String),
    #[error("invalid RubyGems metadata: {0}")]
    InvalidMetadata(String),
    #[error("RubyGems version not found: {name}@{version}")]
    VersionNotFound { name: String, version: String },
    #[error("RubyGems upstream returned HTTP status {0}")]
    UpstreamStatus(u16),
    #[error("RubyGems package has too many variants: {0}")]
    TooManyVariants(usize),
    #[error("RubyGems compact info exceeds supported bounds")]
    CompactInfoTooLarge,
    #[error("RubyGems artifact not found: {0}")]
    ArtifactNotFound(String),
    #[error("RubyGems artifact filename {filename} matched {count} package variants")]
    AmbiguousArtifact { filename: String, count: usize },
    #[error("RubyGems artifact filename produced too many name candidates: {0}")]
    TooManyArtifactCandidates(usize),
    #[error("RubyGems artifact delivery failed: {0}")]
    ArtifactDelivery(#[from] ArtifactDeliveryError),
    #[error("RubyGems response serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl RubyGemsError {
    fn is_not_found(&self) -> bool {
        matches!(self, Self::UpstreamStatus(404 | 410))
            || matches!(self, Self::Upstream(error) if matches!(error.status().map(|status| status.as_u16()), Some(404 | 410)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AllowlistEntry, BlocklistEntry, MissingPublishTime, OsvErrorBehavior};
    use crate::malicious::{OsvError, OsvFinding};
    use axum::http::HeaderValue;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    fn gem(number: &str, platform: &str, yanked: bool) -> GemVersion {
        gem_at(number, platform, yanked, "2026-01-01T00:00:00Z")
    }

    fn gem_at(number: &str, platform: &str, yanked: bool, created_at: &str) -> GemVersion {
        gem_for_at("demo", number, platform, yanked, created_at)
    }

    fn gem_for_at(
        name: &str,
        number: &str,
        platform: &str,
        yanked: bool,
        created_at: &str,
    ) -> GemVersion {
        let suffix = if platform == "ruby" {
            format!("{name}-{number}.gem")
        } else {
            format!("{name}-{number}-{platform}.gem")
        };
        GemVersion {
            number: number.into(),
            platform: platform.into(),
            created_at: created_at.parse().unwrap(),
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

    struct CleanChecker {
        batches: AtomicUsize,
    }

    struct PositionalChecker;

    #[async_trait]
    impl MaliciousChecker for PositionalChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<OsvFinding>, OsvError> {
            panic!("compact filtering must use check_many")
        }

        async fn check_many(
            &self,
            artifacts: &[Artifact],
        ) -> Result<Vec<Vec<OsvFinding>>, OsvError> {
            assert_eq!(
                artifacts
                    .iter()
                    .map(|artifact| artifact.version.as_str())
                    .collect::<Vec<_>>(),
                ["1.0.0", "3.0.0"]
            );
            Ok(vec![
                Vec::new(),
                vec![OsvFinding {
                    osv_id: "MAL-ruby-positional".into(),
                    summary: None,
                    source: "fixture".into(),
                    modified: None,
                    effective_severity: None,
                    evaluation_error: None,
                }],
            ])
        }
    }

    #[async_trait]
    impl MaliciousChecker for CleanChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<OsvFinding>, OsvError> {
            panic!("compact filtering must use check_many")
        }

        async fn check_many(
            &self,
            artifacts: &[Artifact],
        ) -> Result<Vec<Vec<OsvFinding>>, OsvError> {
            self.batches.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(vec![Vec::new(); artifacts.len()])
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

    #[tokio::test]
    async fn artifact_resolution_handles_hyphenated_names_platforms_and_ambiguity() {
        let provider = StaticProvider(HashMap::from([
            (
                "name-with-dash".into(),
                vec![gem_for_at(
                    "name-with-dash",
                    "1.2.3",
                    "arm64-darwin",
                    false,
                    "2026-01-01T00:00:00Z",
                )],
            ),
            (
                "demo".into(),
                vec![gem_for_at(
                    "demo",
                    "1-0-x",
                    "ruby",
                    false,
                    "2026-01-01T00:00:00Z",
                )],
            ),
            (
                "demo-1".into(),
                vec![gem_for_at(
                    "demo-1",
                    "0-x",
                    "ruby",
                    false,
                    "2026-01-01T00:00:00Z",
                )],
            ),
        ]));
        let artifact = resolve_artifact(&provider, "name-with-dash-1.2.3-arm64-darwin.gem")
            .await
            .unwrap();
        assert_eq!(artifact.name, "name-with-dash");
        assert_eq!(artifact.version, "1.2.3");
        assert!(matches!(
            resolve_artifact(&provider, "demo-1-0-x.gem").await,
            Err(RubyGemsError::AmbiguousArtifact { count: 2, .. })
        ));
        assert!(matches!(
            resolve_artifact(&provider, "wrong.gem").await,
            Err(RubyGemsError::ArtifactNotFound(_))
        ));
    }

    #[tokio::test]
    async fn artifact_delivery_rechecks_policy_before_redirect() {
        let provider = StaticProvider(HashMap::from([(
            "demo".into(),
            vec![gem("1.0.0", "ruby", false)],
        )]));
        let mut config = Config::default();
        config.policy.minimum_age = Duration::ZERO;
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
        let delivery = crate::artifacts::ArtifactDeliveryClient::new();
        let allowed = artifact_delivery_response(
            &config,
            &provider,
            &CleanChecker {
                batches: AtomicUsize::new(0),
            },
            "demo-1.0.0.gem",
            Utc::now(),
            ArtifactDeliveryOptions::new(&delivery),
        )
        .await
        .unwrap()
        .into_registry_response()
        .await;
        assert_eq!(allowed.status, 302);
        assert_eq!(
            header_value(&allowed, "location").as_deref(),
            Some("https://rubygems.example/gems/demo-1.0.0.gem")
        );

        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::RubyGems,
            name: "demo".into(),
            versions: vec!["1.0.0".into()],
            reason: "test direct denial".into(),
        });
        let denied = artifact_delivery_response(
            &config,
            &provider,
            &CleanChecker {
                batches: AtomicUsize::new(0),
            },
            "demo-1.0.0.gem",
            Utc::now(),
            ArtifactDeliveryOptions::new(&delivery),
        )
        .await
        .unwrap()
        .into_registry_response()
        .await;
        assert_eq!(denied.status, 403);
        assert!(
            String::from_utf8(denied.body)
                .unwrap()
                .contains("manually_blocked")
        );
    }

    #[tokio::test]
    async fn proxy_delivery_preserves_gem_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/gems/demo-1.0.0.gem",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: 9\r\nconnection: close\r\n\r\ngem-bytes",
                )
                .await
                .unwrap();
        });
        let mut metadata = gem("1.0.0", "ruby", false);
        metadata.gem_uri = url;
        let provider = StaticProvider(HashMap::from([("demo".into(), vec![metadata])]));
        let mut config = Config::default();
        config.artifacts.behavior = crate::config::ArtifactBehavior::Proxy;
        config.policy.minimum_age = Duration::ZERO;
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
        let delivery = crate::artifacts::ArtifactDeliveryClient::new();
        let response = artifact_delivery_response(
            &config,
            &provider,
            &CleanChecker {
                batches: AtomicUsize::new(0),
            },
            "demo-1.0.0.gem",
            Utc::now(),
            ArtifactDeliveryOptions::new(&delivery),
        )
        .await
        .unwrap()
        .into_registry_response()
        .await;
        server.await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"gem-bytes");
        assert_eq!(
            header_value(&response, "content-type").as_deref(),
            Some("application/octet-stream")
        );
    }

    #[tokio::test]
    async fn compact_info_filters_policy_in_one_batch_and_preserves_lines() {
        let raw = concat!(
            "---\n",
            "1.0.0 dep:>= 1|checksum:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ",created_at:2026-01-01T00:00:00Z\n",
            "2.0.0 |checksum:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ",created_at:2026-01-02T00:00:00Z\n",
            "3.0.0-arm64-darwin |checksum:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ",created_at:2026-07-10T12:00:00Z\n"
        );
        let versions = vec![
            gem_at("1.0.0", "ruby", false, "2026-01-01T00:00:00.123Z"),
            gem_at("2.0.0", "ruby", false, "2026-01-02T00:00:00.456Z"),
            gem_at("3.0.0", "arm64-darwin", false, "2026-07-10T12:00:00.789Z"),
        ];
        let mut config = Config::default();
        config.policy.osv.on_error = OsvErrorBehavior::Block;
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::RubyGems,
            name: "demo".into(),
            versions: vec!["2.0.0".into()],
            reason: "test".into(),
        });
        let checker = CleanChecker {
            batches: AtomicUsize::new(0),
        };
        let filtered = filter_compact_info(
            &config,
            &checker,
            "demo",
            raw.as_bytes(),
            versions,
            "2026-07-11T16:00:00Z".parse().unwrap(),
        )
        .await
        .unwrap();
        let text = String::from_utf8(filtered).unwrap();
        assert!(text.contains("1.0.0 dep:>= 1|checksum:"));
        assert!(!text.contains("2.0.0 |"));
        assert!(!text.contains("3.0.0-arm64-darwin |"));
        assert_eq!(checker.batches.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn filtered_response_supports_validators_and_byte_ranges() {
        let body = b"---\n1.0.0 |checksum:abc\n".to_vec();
        let full = filtered_representation_response(body.clone(), &HeaderMap::new());
        assert_eq!(full.status, 200);
        assert_eq!(
            header_value(&full, "content-length"),
            Some(body.len().to_string())
        );
        let etag = header_value(&full, "etag").unwrap();
        assert!(
            header_value(&full, "repr-digest")
                .unwrap()
                .starts_with("sha-256=\"")
        );
        assert_eq!(
            header_value(&full, "cache-control").as_deref(),
            Some("no-cache")
        );

        let mut conditional = HeaderMap::new();
        conditional.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_str(&format!("W/{etag}")).unwrap(),
        );
        assert_eq!(
            filtered_representation_response(body.clone(), &conditional).status,
            304
        );

        let mut ranged = HeaderMap::new();
        ranged.insert(header::RANGE, HeaderValue::from_static("bytes=4-8"));
        ranged.insert(header::IF_RANGE, HeaderValue::from_str(&etag).unwrap());
        let partial = filtered_representation_response(body.clone(), &ranged);
        assert_eq!(partial.status, 206);
        assert_eq!(partial.body, body[4..=8]);
        assert_eq!(
            header_value(&partial, "content-range"),
            Some(format!("bytes 4-8/{}", body.len()))
        );

        ranged.insert(header::IF_RANGE, HeaderValue::from_static("\"stale\""));
        assert_eq!(
            filtered_representation_response(body.clone(), &ranged).status,
            200
        );
        ranged.remove(header::IF_RANGE);
        ranged.insert(header::RANGE, HeaderValue::from_static("bytes=999-"));
        assert_eq!(filtered_representation_response(body, &ranged).status, 416);
    }

    #[tokio::test]
    async fn compact_info_fails_closed_on_metadata_disagreement() {
        let raw = concat!(
            "---\n1.0.0 |checksum:",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ",created_at:2026-01-01T00:00:00Z\n"
        );
        let checker = CleanChecker {
            batches: AtomicUsize::new(0),
        };
        let error = filter_compact_info(
            &Config::default(),
            &checker,
            "demo",
            raw.as_bytes(),
            vec![gem("1.0.0", "ruby", false)],
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("checksum disagrees"));
    }

    #[tokio::test]
    async fn age_transition_invalidates_filtered_etag() {
        let raw = concat!(
            "---\n1.0.0 |checksum:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ",created_at:2026-07-10T00:00:00Z\n"
        );
        let versions = vec![gem_at("1.0.0", "ruby", false, "2026-07-10T00:00:00.123Z")];
        let checker = CleanChecker {
            batches: AtomicUsize::new(0),
        };
        let young = filter_compact_info(
            &Config::default(),
            &checker,
            "demo",
            raw.as_bytes(),
            versions.clone(),
            "2026-07-11T00:00:00Z".parse().unwrap(),
        )
        .await
        .unwrap();
        let young_response = filtered_representation_response(young, &HeaderMap::new());
        let old_etag = header_value(&young_response, "etag").unwrap();

        let aged = filter_compact_info(
            &Config::default(),
            &checker,
            "demo",
            raw.as_bytes(),
            versions,
            "2026-07-14T00:00:01Z".parse().unwrap(),
        )
        .await
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_str(&old_etag).unwrap(),
        );
        let aged_response = filtered_representation_response(aged, &headers);
        assert_eq!(aged_response.status, 200);
        assert_ne!(header_value(&aged_response, "etag").unwrap(), old_etag);
        assert!(
            String::from_utf8(aged_response.body)
                .unwrap()
                .contains("1.0.0 |")
        );
    }

    #[tokio::test]
    async fn batch_results_map_linearly_across_osv_bypass_entries() {
        let artifacts = ["1.0.0", "2.0.0", "3.0.0"]
            .map(|version| Artifact::package(Ecosystem::RubyGems, "demo", version, None));
        let mut config = Config::default();
        config.policy.minimum_age = Duration::ZERO;
        config.policy.missing_publish_time = MissingPublishTime::Allow;
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::RubyGems,
            name: "demo".into(),
            version: "2.0.0".into(),
            bypass_age_gate: false,
            bypass_osv: true,
            reason: "exercise positional mapping".into(),
        });
        let decisions =
            evaluate_artifacts(&config, &PositionalChecker, &artifacts, Utc::now()).await;
        assert!(decisions[0].allowed);
        assert!(decisions[1].allowed);
        assert!(!decisions[2].allowed);
    }

    fn header_value(response: &RegistryResponse, name: &str) -> Option<String> {
        response
            .headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }
}
