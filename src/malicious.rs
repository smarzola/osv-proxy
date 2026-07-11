use crate::artifact::{Artifact, Ecosystem};
use crate::config::{Config, LocalOsvConfig, LocalOsvStaleBehavior, OsvSource};
use crate::go;
use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::stream::{FuturesUnordered, StreamExt};
use node_semver as npm_semver;
use pep440_rs as pep440;
use polycvss::{Vector as CvssVector, Version as CvssVersion};
use reqwest::Client;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use semver::Version as cargo_semver;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use zip::ZipArchive;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const OSV_DUMP_BASE_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities";
const OSV_DETAIL_CONCURRENCY: usize = 16;

#[async_trait]
pub trait OsvChecker: Send + Sync {
    async fn check(&self, artifact: &Artifact) -> Result<Vec<OsvFinding>, OsvError>;

    async fn check_many(&self, artifacts: &[Artifact]) -> Result<Vec<Vec<OsvFinding>>, OsvError> {
        let mut results = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            results.push(self.check(artifact).await?);
        }
        Ok(results)
    }
}

pub use OsvChecker as MaliciousChecker;

pub fn configured_osv_checker(config: &Config) -> Arc<dyn OsvChecker> {
    match config.policy.osv.source {
        OsvSource::Live => Arc::new(OsvHttpClient::with_vulnerability_policy(
            &config.policy.osv.api_url,
            config.policy.osv.block_vulnerabilities,
        )),
        OsvSource::Local => Arc::new(SqliteMaliciousChecker::new(&config.policy.osv.local)),
    }
}

pub fn configured_malicious_checker(config: &Config) -> Arc<dyn MaliciousChecker> {
    configured_osv_checker(config)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsvFinding {
    pub osv_id: String,
    pub summary: Option<String>,
    pub source: String,
    pub modified: Option<DateTime<Utc>>,
    pub effective_severity: Option<OsvEffectiveSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_error: Option<String>,
}

pub type MaliciousHit = OsvFinding;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    #[serde(rename = "score")]
    pub vector: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsvEffectiveSeverity {
    pub severity_type: String,
    pub vector: String,
    pub base_score: f64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid {severity_type} vector {vector}: {message}")]
pub struct OsvSeverityError {
    pub severity_type: String,
    pub vector: String,
    pub message: String,
}

pub fn effective_osv_severity(
    top_level: &[OsvSeverity],
    matching_package: Option<&[OsvSeverity]>,
) -> Result<Option<OsvEffectiveSeverity>, OsvSeverityError> {
    let selected = matching_package
        .filter(|severity| !severity.is_empty())
        .unwrap_or(top_level);
    let mut effective: Option<OsvEffectiveSeverity> = None;
    for severity in selected {
        if !matches!(
            severity.severity_type.as_str(),
            "CVSS_V2" | "CVSS_V3" | "CVSS_V4"
        ) {
            continue;
        }
        let vector = severity
            .vector
            .parse::<CvssVector>()
            .map_err(|error| OsvSeverityError {
                severity_type: severity.severity_type.clone(),
                vector: severity.vector.clone(),
                message: error.to_string(),
            })?;
        let version_matches_type = matches!(
            (severity.severity_type.as_str(), CvssVersion::from(vector)),
            ("CVSS_V2", CvssVersion::V20)
                | ("CVSS_V3", CvssVersion::V30 | CvssVersion::V31)
                | ("CVSS_V4", CvssVersion::V40)
        );
        if !version_matches_type {
            return Err(OsvSeverityError {
                severity_type: severity.severity_type.clone(),
                vector: severity.vector.clone(),
                message: "vector version does not match severity type".to_string(),
            });
        }
        let candidate = OsvEffectiveSeverity {
            severity_type: severity.severity_type.clone(),
            vector: severity.vector.clone(),
            base_score: f64::from(vector.base_score()),
        };
        let replace = effective.as_ref().is_none_or(|current| {
            candidate.base_score > current.base_score
                || (candidate.base_score == current.base_score
                    && (&candidate.severity_type, &candidate.vector)
                        < (&current.severity_type, &current.vector))
        });
        if replace {
            effective = Some(candidate);
        }
    }
    Ok(effective)
}

#[derive(Debug, Error)]
pub enum OsvError {
    #[error("OSV request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("OSV batch response returned {actual} results for {expected} queries")]
    InvalidBatchResponse { expected: usize, actual: usize },
    #[error("local malicious store failed: {0}")]
    LocalStore(String),
    #[error("local malicious store could not evaluate range for {package}: {message}")]
    RangeEvaluation { package: String, message: String },
    #[error("OSV dump sync failed: {0}")]
    Sync(String),
    #[error("OSV severity evaluation failed: {0}")]
    Severity(#[from] OsvSeverityError),
    #[error("OSV pagination token repeated for {query}: {token}")]
    PaginationCycle { query: String, token: String },
    #[error("OSV detail response ID mismatch: requested {requested}, returned {actual}")]
    DetailIdentity { requested: String, actual: String },
}

pub type MaliciousError = OsvError;

#[derive(Debug, Clone)]
pub struct OsvHttpClient {
    api_url: String,
    client: Client,
    block_vulnerabilities: bool,
}

impl OsvHttpClient {
    pub fn new(api_url: impl Into<String>) -> Self {
        Self::with_vulnerability_policy(api_url, true)
    }

    pub fn with_vulnerability_policy(
        api_url: impl Into<String>,
        block_vulnerabilities: bool,
    ) -> Self {
        Self {
            api_url: api_url.into().trim_end_matches('/').to_string(),
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("OSV HTTP client should build with static timeout configuration"),
            block_vulnerabilities,
        }
    }

    async fn post_query(&self, request: &OsvQueryRequest) -> Result<OsvQueryResponse, OsvError> {
        Ok(self
            .client
            .post(format!("{}/v1/query", self.api_url))
            .json(request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    async fn post_batch(
        &self,
        queries: Vec<OsvQueryRequest>,
    ) -> Result<OsvBatchQueryResponse, OsvError> {
        Ok(self
            .client
            .post(format!("{}/v1/querybatch", self.api_url))
            .json(&OsvBatchQueryRequest { queries })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    async fn hydrate_details(
        &self,
        ids: BTreeSet<String>,
    ) -> BTreeMap<String, Result<OsvVulnerability, String>> {
        let mut pending = ids.into_iter();
        let mut in_flight = FuturesUnordered::new();
        let mut details = BTreeMap::new();
        loop {
            while in_flight.len() < OSV_DETAIL_CONCURRENCY {
                let Some(id) = pending.next() else { break };
                let client = self.client.clone();
                let base = self.api_url.clone();
                in_flight.push(async move {
                    let result = async {
                        let mut url =
                            reqwest::Url::parse(&base).map_err(|error| error.to_string())?;
                        url.path_segments_mut()
                            .map_err(|_| "OSV API URL cannot be a base URL".to_string())?
                            .extend(["v1", "vulns", id.as_str()]);
                        let detail = client
                            .get(url)
                            .send()
                            .await
                            .map_err(|error| error.to_string())?
                            .error_for_status()
                            .map_err(|error| error.to_string())?
                            .json::<OsvVulnerability>()
                            .await
                            .map_err(|error| error.to_string())?;
                        if detail.id != id {
                            return Err(OsvError::DetailIdentity {
                                requested: id.clone(),
                                actual: detail.id,
                            }
                            .to_string());
                        }
                        Ok(detail)
                    }
                    .await;
                    (id, result)
                });
            }
            let Some(result) = in_flight.next().await else {
                break;
            };
            let (id, result) = result;
            details.insert(id, result);
        }
        details
    }
}

#[async_trait]
impl OsvChecker for OsvHttpClient {
    async fn check(&self, artifact: &Artifact) -> Result<Vec<OsvFinding>, OsvError> {
        let mut request = OsvQueryRequest {
            package: OsvPackage {
                name: artifact.name.clone(),
                ecosystem: artifact.ecosystem.osv_name().to_string(),
            },
            version: osv_query_version(artifact),
            page_token: None,
        };
        let mut findings = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        loop {
            let response = self.post_query(&request).await?;
            for vulnerability in response.vulns {
                if !self.block_vulnerabilities {
                    if vulnerability.id.starts_with("MAL-") && vulnerability.withdrawn.is_none() {
                        findings.push(stub_finding(vulnerability));
                    }
                    continue;
                }
                let id = vulnerability.id.clone();
                match finding_from_vulnerability(vulnerability, artifact) {
                    Ok(Some(finding)) => findings.push(finding),
                    Ok(None) => {}
                    Err(error) => findings.push(error_finding(id, error.to_string())),
                }
            }
            let Some(token) = response.next_page_token.filter(|token| !token.is_empty()) else {
                break;
            };
            if !seen_tokens.insert(token.clone()) {
                return Err(OsvError::PaginationCycle {
                    query: artifact.identity(),
                    token,
                });
            }
            request.page_token = Some(token);
        }
        findings.sort_by(|left, right| left.osv_id.cmp(&right.osv_id));
        findings.dedup_by(|left, right| left.osv_id == right.osv_id);
        Ok(findings)
    }

    async fn check_many(&self, artifacts: &[Artifact]) -> Result<Vec<Vec<OsvFinding>>, OsvError> {
        if artifacts.is_empty() {
            return Ok(Vec::new());
        }

        let base_queries = artifacts
            .iter()
            .map(|artifact| OsvQueryRequest {
                package: OsvPackage {
                    name: artifact.name.clone(),
                    ecosystem: artifact.ecosystem.osv_name().to_string(),
                },
                version: osv_query_version(artifact),
                page_token: None,
            })
            .collect::<Vec<_>>();
        let response = self.post_batch(base_queries.clone()).await?;
        if response.results.len() != artifacts.len() {
            return Err(OsvError::InvalidBatchResponse {
                expected: artifacts.len(),
                actual: response.results.len(),
            });
        }

        let mut stubs = vec![Vec::<OsvVulnerability>::new(); artifacts.len()];
        let mut pending = Vec::new();
        let mut seen_tokens = vec![BTreeSet::new(); artifacts.len()];
        for (index, result) in response.results.into_iter().enumerate() {
            stubs[index].extend(result.vulns);
            if let Some(token) = result.next_page_token.filter(|token| !token.is_empty()) {
                seen_tokens[index].insert(token.clone());
                pending.push((index, token));
            }
        }
        while !pending.is_empty() {
            let queries = pending
                .iter()
                .map(|(index, token)| {
                    let mut query = base_queries[*index].clone();
                    query.page_token = Some(token.clone());
                    query
                })
                .collect::<Vec<_>>();
            let response = self.post_batch(queries).await?;
            if response.results.len() != pending.len() {
                return Err(OsvError::InvalidBatchResponse {
                    expected: pending.len(),
                    actual: response.results.len(),
                });
            }
            let mut next = Vec::new();
            for ((index, _), result) in pending.into_iter().zip(response.results) {
                stubs[index].extend(result.vulns);
                if let Some(token) = result.next_page_token.filter(|token| !token.is_empty()) {
                    if !seen_tokens[index].insert(token.clone()) {
                        return Err(OsvError::PaginationCycle {
                            query: artifacts[index].identity(),
                            token,
                        });
                    }
                    next.push((index, token));
                }
            }
            pending = next;
        }

        let detail_ids = stubs
            .iter()
            .flatten()
            .filter(|stub| self.block_vulnerabilities && !stub.id.starts_with("MAL-"))
            .map(|stub| stub.id.clone())
            .collect::<BTreeSet<_>>();
        let details = self.hydrate_details(detail_ids).await;
        let mut results = Vec::with_capacity(artifacts.len());
        for (artifact, artifact_stubs) in artifacts.iter().zip(stubs) {
            let mut findings = Vec::new();
            for stub in artifact_stubs {
                if stub.id.starts_with("MAL-") {
                    findings.push(stub_finding(stub));
                } else if let Some(detail) = details.get(&stub.id) {
                    match detail {
                        Ok(detail) => match finding_from_vulnerability(detail.clone(), artifact) {
                            Ok(Some(finding)) => findings.push(finding),
                            Ok(None) => {}
                            Err(error) => {
                                findings.push(error_finding(stub.id.clone(), error.to_string()))
                            }
                        },
                        Err(error) => findings.push(error_finding(stub.id.clone(), error.clone())),
                    }
                }
            }
            findings.sort_by(|left, right| left.osv_id.cmp(&right.osv_id));
            findings.dedup_by(|left, right| left.osv_id == right.osv_id);
            results.push(findings);
        }
        Ok(results)
    }
}

fn stub_finding(vulnerability: OsvVulnerability) -> OsvFinding {
    OsvFinding {
        osv_id: vulnerability.id,
        summary: vulnerability.summary,
        source: "osv".to_string(),
        modified: vulnerability.modified,
        effective_severity: None,
        evaluation_error: None,
    }
}

fn error_finding(osv_id: String, error: String) -> OsvFinding {
    OsvFinding {
        osv_id,
        summary: None,
        source: "osv".to_string(),
        modified: None,
        effective_severity: None,
        evaluation_error: Some(error),
    }
}

fn finding_from_vulnerability(
    vulnerability: OsvVulnerability,
    artifact: &Artifact,
) -> Result<Option<OsvFinding>, OsvError> {
    if vulnerability.withdrawn.is_some() {
        return Ok(None);
    }
    if vulnerability.id.starts_with("MAL-") {
        return Ok(Some(stub_finding(vulnerability)));
    }
    let matching = vulnerability
        .affected
        .iter()
        .filter(|affected| {
            affected.package.ecosystem == artifact.ecosystem.osv_name()
                && artifact.ecosystem.normalize_name(&affected.package.name) == artifact.name
        })
        .collect::<Vec<_>>();
    let mut effective_severity = None;
    if matching.is_empty() {
        effective_severity = effective_osv_severity(&vulnerability.severity, None)?;
    } else {
        for affected in matching {
            let candidate = effective_osv_severity(
                &vulnerability.severity,
                Some(affected.severity.as_slice()),
            )?;
            if candidate.as_ref().is_some_and(|candidate| {
                effective_severity
                    .as_ref()
                    .is_none_or(|current: &OsvEffectiveSeverity| {
                        candidate.base_score > current.base_score
                            || (candidate.base_score == current.base_score
                                && (&candidate.severity_type, &candidate.vector)
                                    < (&current.severity_type, &current.vector))
                    })
            }) {
                effective_severity = candidate;
            }
        }
    }
    Ok(Some(OsvFinding {
        osv_id: vulnerability.id,
        summary: vulnerability.summary,
        source: "osv".to_string(),
        modified: vulnerability.modified,
        effective_severity,
        evaluation_error: None,
    }))
}

#[derive(Debug, Clone)]
pub struct SqliteMaliciousChecker {
    path: PathBuf,
    max_staleness: Duration,
    on_stale: LocalOsvStaleBehavior,
}

impl SqliteMaliciousChecker {
    pub fn new(config: &LocalOsvConfig) -> Self {
        Self {
            path: config.sqlite_path.clone(),
            max_staleness: config.max_staleness,
            on_stale: config.on_stale,
        }
    }

    pub fn initialize(path: impl AsRef<Path>) -> Result<(), OsvError> {
        let mut connection = open_read_write_connection(path.as_ref())?;
        initialize_schema(&mut connection)
    }

    fn open_read_only(&self) -> Result<Connection, OsvError> {
        open_read_only_connection(&self.path)
    }

    fn check_with_connection(
        &self,
        connection: &Connection,
        artifact: &Artifact,
    ) -> Result<Vec<OsvFinding>, OsvError> {
        ensure_store_healthy(connection, artifact.ecosystem.osv_name(), self)?;
        let hits = exact_hits(connection, artifact)?;
        if !hits.is_empty() {
            return Ok(hits);
        }
        range_hits(connection, artifact)
    }

    fn check_many_with_connection(
        &self,
        connection: &Connection,
        artifacts: &[Artifact],
    ) -> Result<Vec<Vec<OsvFinding>>, OsvError> {
        let ecosystems = artifacts
            .iter()
            .map(|artifact| artifact.ecosystem.osv_name())
            .collect::<BTreeSet<_>>();
        for ecosystem in ecosystems {
            ensure_store_healthy(connection, ecosystem, self)?;
        }

        let mut grouped = BTreeMap::<(String, String, String), Vec<usize>>::new();
        for (index, artifact) in artifacts.iter().enumerate() {
            grouped
                .entry((
                    artifact.ecosystem.osv_name().to_string(),
                    artifact.name.clone(),
                    artifact.version.clone(),
                ))
                .or_default()
                .push(index);
        }

        let mut range_results = BTreeMap::<(String, String, String), Vec<OsvFinding>>::new();
        let mut results = vec![Vec::new(); artifacts.len()];
        for (_, indexes) in grouped {
            let artifact = &artifacts[indexes[0]];
            let hits = exact_hits(connection, artifact)?;
            if hits.is_empty() {
                let range_key = (
                    artifact.ecosystem.osv_name().to_string(),
                    artifact.name.clone(),
                    artifact.version.clone(),
                );
                let hits = if let Some(hits) = range_results.get(&range_key) {
                    hits.clone()
                } else {
                    let hits = range_hits(connection, artifact)?;
                    range_results.insert(range_key, hits.clone());
                    hits
                };
                for index in indexes {
                    results[index] = hits.clone();
                }
            } else {
                for index in indexes {
                    results[index] = hits.clone();
                }
            }
        }
        Ok(results)
    }
}

#[async_trait]
impl OsvChecker for SqliteMaliciousChecker {
    async fn check(&self, artifact: &Artifact) -> Result<Vec<OsvFinding>, OsvError> {
        let connection = self.open_read_only()?;
        self.check_with_connection(&connection, artifact)
    }

    async fn check_many(&self, artifacts: &[Artifact]) -> Result<Vec<Vec<OsvFinding>>, OsvError> {
        if artifacts.is_empty() {
            return Ok(Vec::new());
        }
        let connection = self.open_read_only()?;
        self.check_many_with_connection(&connection, artifacts)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaliciousSyncReport {
    pub ecosystems: Vec<MaliciousSyncEcosystemReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaliciousSyncEcosystemReport {
    pub ecosystem: String,
    pub mode: MaliciousSyncMode,
    pub imported: usize,
    pub withdrawn: usize,
    pub skipped_non_malicious: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaliciousSyncMode {
    Bootstrap,
    Incremental,
}

#[async_trait]
pub trait OsvDumpClient: Send + Sync {
    async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, OsvError>;
}

#[derive(Debug, Clone)]
pub struct HttpOsvDumpClient {
    client: Client,
}

impl HttpOsvDumpClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("OSV dump HTTP client should build with static timeout configuration"),
        }
    }
}

impl Default for HttpOsvDumpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OsvDumpClient for HttpOsvDumpClient {
    async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, OsvError> {
        let response = self.client.get(url).send().await?.error_for_status()?;
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(OsvError::Request)
    }
}

pub async fn sync_malicious(
    config: &LocalOsvConfig,
    client: &dyn OsvDumpClient,
) -> Result<MaliciousSyncReport, OsvError> {
    SqliteMaliciousChecker::initialize(&config.sqlite_path)?;
    let mut connection = open_read_write_connection(&config.sqlite_path)?;
    let mut ecosystems = Vec::new();
    for ecosystem in [
        Ecosystem::Npm,
        Ecosystem::Pypi,
        Ecosystem::Go,
        Ecosystem::CratesIo,
        Ecosystem::Nuget,
    ] {
        ecosystems.push(
            sync_ecosystem(
                &mut connection,
                client,
                ecosystem,
                config.retain_raw_advisories,
            )
            .await?,
        );
    }
    Ok(MaliciousSyncReport { ecosystems })
}

async fn sync_ecosystem(
    connection: &mut Connection,
    client: &dyn OsvDumpClient,
    ecosystem: Ecosystem,
    retain_raw_advisories: bool,
) -> Result<MaliciousSyncEcosystemReport, OsvError> {
    let attempted_at = Utc::now();
    let result = if sync_state(connection, ecosystem.osv_name())?
        .and_then(|state| state.last_success_at)
        .is_some()
    {
        sync_incremental(
            connection,
            client,
            ecosystem,
            attempted_at,
            retain_raw_advisories,
        )
        .await
    } else {
        sync_bootstrap(
            connection,
            client,
            ecosystem,
            attempted_at,
            retain_raw_advisories,
        )
        .await
    };

    match result {
        Ok(report) => Ok(report),
        Err(err) => {
            record_sync_failure(connection, ecosystem.osv_name(), attempted_at, &err)?;
            Err(err)
        }
    }
}

async fn sync_bootstrap(
    connection: &mut Connection,
    client: &dyn OsvDumpClient,
    ecosystem: Ecosystem,
    attempted_at: DateTime<Utc>,
    retain_raw_advisories: bool,
) -> Result<MaliciousSyncEcosystemReport, OsvError> {
    let bytes = client.fetch_bytes(&all_zip_url(ecosystem)).await?;
    let advisories = advisories_from_zip(&bytes, retain_raw_advisories)?;
    let stats = import_advisories_and_record_success(
        connection,
        ecosystem,
        &advisories,
        attempted_at,
        ecosystem.osv_name(),
        Some(serialize_high_watermark(attempted_at)),
    )?;
    Ok(MaliciousSyncEcosystemReport {
        ecosystem: ecosystem.osv_name().to_string(),
        mode: MaliciousSyncMode::Bootstrap,
        imported: stats.imported,
        withdrawn: stats.withdrawn,
        skipped_non_malicious: stats.skipped_non_malicious,
    })
}

async fn sync_incremental(
    connection: &mut Connection,
    client: &dyn OsvDumpClient,
    ecosystem: Ecosystem,
    attempted_at: DateTime<Utc>,
    retain_raw_advisories: bool,
) -> Result<MaliciousSyncEcosystemReport, OsvError> {
    let previous_high_watermark =
        sync_state(connection, ecosystem.osv_name())?.and_then(|state| state.high_watermark);
    let modified_csv = client.fetch_bytes(&modified_id_csv_url(ecosystem)).await?;
    let rows = parse_modified_id_csv(&modified_csv, previous_high_watermark.as_deref())?;
    let mut advisories = Vec::new();
    for row in &rows {
        if !row.osv_id.starts_with("MAL-") {
            continue;
        }
        let bytes = client
            .fetch_bytes(&advisory_json_url(ecosystem, &row.osv_id))
            .await?;
        advisories.push(parse_osv_advisory_bytes(&bytes, retain_raw_advisories)?);
    }
    let high_watermark = rows
        .iter()
        .map(|row| row.modified_at)
        .max()
        .map(serialize_high_watermark)
        .or(previous_high_watermark);
    let stats = import_advisories_and_record_success(
        connection,
        ecosystem,
        &advisories,
        attempted_at,
        ecosystem.osv_name(),
        high_watermark,
    )?;
    Ok(MaliciousSyncEcosystemReport {
        ecosystem: ecosystem.osv_name().to_string(),
        mode: MaliciousSyncMode::Incremental,
        imported: stats.imported,
        withdrawn: stats.withdrawn,
        skipped_non_malicious: stats.skipped_non_malicious,
    })
}

fn all_zip_url(ecosystem: Ecosystem) -> String {
    format!("{}/{}/all.zip", OSV_DUMP_BASE_URL, ecosystem.osv_name())
}

fn modified_id_csv_url(ecosystem: Ecosystem) -> String {
    format!(
        "{}/{}/modified_id.csv",
        OSV_DUMP_BASE_URL,
        ecosystem.osv_name()
    )
}

fn advisory_json_url(ecosystem: Ecosystem, osv_id: &str) -> String {
    format!(
        "{}/{}/{}.json",
        OSV_DUMP_BASE_URL,
        ecosystem.osv_name(),
        osv_id
    )
}

fn advisories_from_zip(
    bytes: &[u8],
    retain_raw_advisories: bool,
) -> Result<Vec<OsvDumpAdvisory>, OsvError> {
    let reader = Cursor::new(bytes);
    let mut archive = ZipArchive::new(reader)
        .map_err(|err| OsvError::Sync(format!("invalid OSV all.zip: {err}")))?;
    let mut advisories = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|err| OsvError::Sync(format!("invalid OSV zip entry: {err}")))?;
        if !file.name().ends_with(".json") {
            continue;
        }
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)
            .map_err(|err| OsvError::Sync(format!("failed to read OSV zip entry: {err}")))?;
        advisories.push(parse_osv_advisory_bytes(&raw, retain_raw_advisories)?);
    }
    Ok(advisories)
}

fn parse_osv_advisory_bytes(
    bytes: &[u8],
    retain_raw_advisories: bool,
) -> Result<OsvDumpAdvisory, OsvError> {
    let mut advisory: OsvDumpAdvisory = serde_json::from_slice(bytes)
        .map_err(|err| OsvError::Sync(format!("invalid OSV advisory JSON: {err}")))?;
    advisory.raw_json = if retain_raw_advisories {
        std::str::from_utf8(bytes)
            .map_err(|err| OsvError::Sync(format!("invalid OSV advisory JSON UTF-8: {err}")))?
            .to_string()
    } else {
        "{}".to_string()
    };
    Ok(advisory)
}

#[derive(Debug, Clone)]
struct ModifiedIdRow {
    modified_at: DateTime<Utc>,
    osv_id: String,
}

fn parse_modified_id_csv(
    bytes: &[u8],
    previous_high_watermark: Option<&str>,
) -> Result<Vec<ModifiedIdRow>, OsvError> {
    let raw = std::str::from_utf8(bytes)
        .map_err(|err| OsvError::Sync(format!("invalid modified_id.csv UTF-8: {err}")))?;
    let previous_high_watermark = previous_high_watermark
        .map(parse_modified_timestamp)
        .transpose()?;
    let mut rows = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut columns = line.split(',');
        let modified_at = columns.next().unwrap_or_default().trim();
        let id = columns.next().unwrap_or_default().trim();
        if modified_at.eq_ignore_ascii_case("modified") || id.eq_ignore_ascii_case("id") {
            continue;
        }
        if modified_at.is_empty() || id.is_empty() {
            return Err(OsvError::Sync(format!(
                "invalid modified_id.csv row: {line}"
            )));
        }
        let modified_at = parse_modified_timestamp(modified_at)?;
        if previous_high_watermark.is_some_and(|previous| modified_at <= previous) {
            continue;
        }
        let osv_id = id.rsplit('/').next().unwrap_or(id).to_string();
        rows.push(ModifiedIdRow {
            modified_at,
            osv_id,
        });
    }
    Ok(rows)
}

fn parse_modified_timestamp(value: &str) -> Result<DateTime<Utc>, OsvError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|err| OsvError::Sync(format!("invalid modified_id.csv timestamp {value}: {err}")))
}

fn serialize_high_watermark(timestamp: DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvDumpAdvisory {
    id: String,
    summary: Option<String>,
    modified: Option<String>,
    published: Option<String>,
    withdrawn: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvDumpAffected>,
    #[serde(skip)]
    raw_json: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvDumpAffected {
    package: OsvDumpPackage,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    ranges: Vec<OsvDumpRange>,
}

#[cfg(test)]
fn effective_advisory_severity(
    advisory: &OsvDumpAdvisory,
    ecosystem: &str,
    package_name: &str,
) -> Result<Option<OsvEffectiveSeverity>, OsvSeverityError> {
    let matching = advisory
        .affected
        .iter()
        .find(|affected| {
            affected.package.ecosystem == ecosystem && affected.package.name == package_name
        })
        .map(|affected| affected.severity.as_slice());
    effective_osv_severity(&advisory.severity, matching)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvDumpPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct OsvDumpRange {
    #[serde(rename = "type")]
    range_type: String,
    #[serde(default)]
    events: Vec<BTreeMap<String, String>>,
}

#[derive(Debug, Default)]
struct ImportStats {
    imported: usize,
    withdrawn: usize,
    skipped_non_malicious: usize,
}

fn import_advisories_and_record_success(
    connection: &mut Connection,
    ecosystem: Ecosystem,
    advisories: &[OsvDumpAdvisory],
    imported_at: DateTime<Utc>,
    state_ecosystem: &str,
    high_watermark: Option<String>,
) -> Result<ImportStats, OsvError> {
    let transaction = connection.transaction().map_err(sqlite_error)?;
    let stats = import_advisories(&transaction, ecosystem, advisories, imported_at)?;
    record_sync_success(&transaction, state_ecosystem, imported_at, high_watermark)?;
    transaction.commit().map_err(sqlite_error)?;
    Ok(stats)
}

fn import_advisories(
    transaction: &rusqlite::Transaction<'_>,
    ecosystem: Ecosystem,
    advisories: &[OsvDumpAdvisory],
    imported_at: DateTime<Utc>,
) -> Result<ImportStats, OsvError> {
    let mut stats = ImportStats::default();
    for advisory in advisories {
        if !advisory.id.starts_with("MAL-") {
            stats.skipped_non_malicious += 1;
            continue;
        }
        replace_advisory(transaction, ecosystem, advisory, imported_at)?;
        if advisory.withdrawn.is_some() {
            stats.withdrawn += 1;
        } else {
            stats.imported += 1;
        }
    }
    Ok(stats)
}

fn replace_advisory(
    transaction: &rusqlite::Transaction<'_>,
    ecosystem: Ecosystem,
    advisory: &OsvDumpAdvisory,
    imported_at: DateTime<Utc>,
) -> Result<(), OsvError> {
    transaction
        .execute("DELETE FROM advisories WHERE osv_id = ?1", [&advisory.id])
        .map_err(sqlite_error)?;
    transaction
        .execute(
            r#"
INSERT INTO advisories (
    osv_id,
    summary,
    modified,
    published,
    withdrawn,
    raw_json,
    source,
    imported_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'osv-gcs', ?7)
"#,
            params![
                advisory.id,
                advisory.summary,
                advisory.modified,
                advisory.published,
                advisory.withdrawn,
                advisory.raw_json,
                imported_at.to_rfc3339()
            ],
        )
        .map_err(sqlite_error)?;

    if advisory.withdrawn.is_some() {
        return Ok(());
    }

    for affected in &advisory.affected {
        if affected.package.ecosystem != ecosystem.osv_name() {
            continue;
        }
        let normalized_name = ecosystem.normalize_name(&affected.package.name);
        transaction
            .execute(
                "INSERT INTO affected_packages (osv_id, ecosystem, name) VALUES (?1, ?2, ?3)",
                params![advisory.id, ecosystem.osv_name(), normalized_name],
            )
            .map_err(sqlite_error)?;
        let package_id = transaction.last_insert_rowid();
        for version in &affected.versions {
            transaction
                .execute(
                    "INSERT INTO affected_versions (affected_package_id, version) VALUES (?1, ?2)",
                    params![package_id, version],
                )
                .map_err(sqlite_error)?;
        }
        for range in &affected.ranges {
            transaction
                .execute(
                    "INSERT INTO affected_ranges (affected_package_id, range_type) VALUES (?1, ?2)",
                    params![package_id, range.range_type],
                )
                .map_err(sqlite_error)?;
            let range_id = transaction.last_insert_rowid();
            for (index, event) in range.events.iter().enumerate() {
                let (event_type, version) = single_range_event(event)?;
                transaction
                    .execute(
                        "INSERT INTO affected_range_events (range_id, event_order, event_type, version) VALUES (?1, ?2, ?3, ?4)",
                        params![range_id, index as i64, event_type, version],
                    )
                    .map_err(sqlite_error)?;
            }
        }
    }
    Ok(())
}

fn single_range_event(event: &BTreeMap<String, String>) -> Result<(&str, &str), OsvError> {
    if event.len() != 1 {
        return Err(OsvError::Sync(format!(
            "OSV range event must have exactly one key, got {}",
            event.len()
        )));
    }
    let (event_type, version) = event.iter().next().expect("event length checked above");
    Ok((event_type.as_str(), version.as_str()))
}

#[derive(Debug)]
struct SyncStateRow {
    high_watermark: Option<String>,
    last_success_at: Option<String>,
}

fn sync_state(connection: &Connection, ecosystem: &str) -> Result<Option<SyncStateRow>, OsvError> {
    connection
        .query_row(
            "SELECT high_watermark, last_success_at FROM sync_state WHERE ecosystem = ?1",
            [ecosystem],
            |row| {
                Ok(SyncStateRow {
                    high_watermark: row.get(0)?,
                    last_success_at: row.get(1)?,
                })
            },
        )
        .optional()
        .map_err(sqlite_error)
}

fn record_sync_success(
    transaction: &rusqlite::Transaction<'_>,
    ecosystem: &str,
    attempted_at: DateTime<Utc>,
    high_watermark: Option<String>,
) -> Result<(), OsvError> {
    transaction
        .execute(
            r#"
INSERT INTO sync_state (
    ecosystem,
    source,
    high_watermark,
    last_success_at,
    last_attempted_at,
    status,
    error_summary
) VALUES (?1, 'osv-gcs', ?2, ?3, ?3, 'healthy', NULL)
ON CONFLICT(ecosystem) DO UPDATE SET
    source = excluded.source,
    high_watermark = excluded.high_watermark,
    last_success_at = excluded.last_success_at,
    last_attempted_at = excluded.last_attempted_at,
    status = excluded.status,
    error_summary = excluded.error_summary
"#,
            params![ecosystem, high_watermark, attempted_at.to_rfc3339()],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn record_sync_failure(
    connection: &Connection,
    ecosystem: &str,
    attempted_at: DateTime<Utc>,
    error: &OsvError,
) -> Result<(), OsvError> {
    let existing = sync_state(connection, ecosystem)?;
    let status = if existing
        .as_ref()
        .and_then(|state| state.last_success_at.as_ref())
        .is_some()
    {
        "healthy"
    } else {
        "failed"
    };
    connection
        .execute(
            r#"
INSERT INTO sync_state (
    ecosystem,
    source,
    high_watermark,
    last_success_at,
    last_attempted_at,
    status,
    error_summary
) VALUES (?1, 'osv-gcs', NULL, NULL, ?2, ?3, ?4)
ON CONFLICT(ecosystem) DO UPDATE SET
    source = excluded.source,
    last_attempted_at = excluded.last_attempted_at,
    status = ?3,
    error_summary = excluded.error_summary
"#,
            params![
                ecosystem,
                attempted_at.to_rfc3339(),
                status,
                error.to_string()
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn open_read_write_connection(path: &Path) -> Result<Connection, OsvError> {
    let connection = Connection::open(path).map_err(sqlite_error)?;
    configure_connection(&connection)?;
    Ok(connection)
}

fn open_read_only_connection(path: &Path) -> Result<Connection, OsvError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite_error)?;
    configure_connection(&connection)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection) -> Result<(), OsvError> {
    connection
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(sqlite_error)?;
    Ok(())
}

fn initialize_schema(connection: &mut Connection) -> Result<(), OsvError> {
    connection
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(sqlite_error)?;
    connection
        .execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS advisories (
    osv_id TEXT PRIMARY KEY NOT NULL,
    summary TEXT,
    modified TEXT,
    published TEXT,
    withdrawn TEXT,
    raw_json TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'osv',
    imported_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS affected_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    osv_id TEXT NOT NULL REFERENCES advisories(osv_id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_affected_packages_lookup
ON affected_packages(ecosystem, name);

CREATE UNIQUE INDEX IF NOT EXISTS idx_affected_packages_unique
ON affected_packages(osv_id, ecosystem, name);

CREATE TABLE IF NOT EXISTS affected_versions (
    affected_package_id INTEGER NOT NULL REFERENCES affected_packages(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    PRIMARY KEY (affected_package_id, version)
);

CREATE INDEX IF NOT EXISTS idx_affected_versions_version
ON affected_versions(version);

CREATE TABLE IF NOT EXISTS affected_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    affected_package_id INTEGER NOT NULL REFERENCES affected_packages(id) ON DELETE CASCADE,
    range_type TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_affected_ranges_package
ON affected_ranges(affected_package_id);

CREATE TABLE IF NOT EXISTS affected_range_events (
    range_id INTEGER NOT NULL REFERENCES affected_ranges(id) ON DELETE CASCADE,
    event_order INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    version TEXT NOT NULL,
    PRIMARY KEY (range_id, event_order)
);

CREATE TABLE IF NOT EXISTS sync_state (
    ecosystem TEXT PRIMARY KEY NOT NULL,
    source TEXT NOT NULL,
    high_watermark TEXT,
    last_success_at TEXT,
    last_attempted_at TEXT,
    status TEXT NOT NULL,
    error_summary TEXT
);
"#,
        )
        .map_err(sqlite_error)
}

fn ensure_store_healthy(
    connection: &Connection,
    ecosystem: &str,
    checker: &SqliteMaliciousChecker,
) -> Result<(), OsvError> {
    let state = connection
        .query_row(
            "SELECT last_success_at, status FROM sync_state WHERE ecosystem = ?1",
            [ecosystem],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| {
            OsvError::LocalStore(format!("missing sync_state row for ecosystem {ecosystem}"))
        })?;

    let (last_success_at, status) = state;
    if status != "healthy" {
        return Err(OsvError::LocalStore(format!(
            "sync_state for ecosystem {ecosystem} is {status}"
        )));
    }
    let last_success_at = last_success_at.ok_or_else(|| {
        OsvError::LocalStore(format!(
            "sync_state for ecosystem {ecosystem} is missing last_success_at"
        ))
    })?;
    let last_success_at = parse_timestamp(&last_success_at)?;
    let age = Utc::now()
        .signed_duration_since(last_success_at)
        .to_std()
        .map_err(|_| {
            OsvError::LocalStore(format!(
                "sync_state for ecosystem {ecosystem} has a future last_success_at"
            ))
        })?;
    if age > checker.max_staleness && checker.on_stale == LocalOsvStaleBehavior::Block {
        return Err(OsvError::LocalStore(format!(
            "local malicious data for ecosystem {ecosystem} is stale"
        )));
    }
    Ok(())
}

fn exact_hits(connection: &Connection, artifact: &Artifact) -> Result<Vec<OsvFinding>, OsvError> {
    let mut statement = connection
        .prepare(
            r#"
SELECT a.osv_id, a.summary, a.source, a.modified
FROM affected_packages ap
JOIN affected_versions av ON av.affected_package_id = ap.id
JOIN advisories a ON a.osv_id = ap.osv_id
WHERE ap.ecosystem = ?1
  AND ap.name = ?2
  AND av.version = ?3
  AND a.withdrawn IS NULL
ORDER BY a.osv_id
"#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                artifact.ecosystem.osv_name(),
                artifact.name,
                osv_query_version(artifact)
            ],
            |row| {
                let modified = row
                    .get::<_, Option<String>>(3)?
                    .map(|value| parse_timestamp(&value))
                    .transpose()
                    .map_err(|err| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(err),
                        )
                    })?;
                Ok(OsvFinding {
                    osv_id: row.get(0)?,
                    summary: row.get(1)?,
                    source: row.get(2)?,
                    modified,
                    effective_severity: None,
                    evaluation_error: None,
                })
            },
        )
        .map_err(sqlite_error)?;

    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

#[derive(Debug, Clone)]
struct StoredRange {
    advisory: OsvFinding,
    range_type: String,
    events: Vec<RangeEvent>,
}

#[derive(Debug, Clone)]
struct RangeEvent {
    event_type: String,
    version: String,
}

fn range_hits(connection: &Connection, artifact: &Artifact) -> Result<Vec<OsvFinding>, OsvError> {
    let ranges = stored_ranges(connection, artifact)?;
    let mut hits = Vec::new();
    for range in ranges {
        if range_matches_artifact(&range, artifact)? {
            hits.push(range.advisory);
        }
    }
    hits.sort_by(|left, right| left.osv_id.cmp(&right.osv_id));
    Ok(hits)
}

fn stored_ranges(
    connection: &Connection,
    artifact: &Artifact,
) -> Result<Vec<StoredRange>, OsvError> {
    let mut statement = connection
        .prepare(
            r#"
SELECT ar.id, a.osv_id, a.summary, a.source, a.modified, ar.range_type
FROM affected_packages ap
JOIN affected_ranges ar ON ar.affected_package_id = ap.id
JOIN advisories a ON a.osv_id = ap.osv_id
WHERE ap.ecosystem = ?1
  AND ap.name = ?2
  AND a.withdrawn IS NULL
ORDER BY a.osv_id, ar.id
"#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![artifact.ecosystem.osv_name(), artifact.name],
            |row| {
                let modified = row
                    .get::<_, Option<String>>(4)?
                    .map(|value| parse_timestamp(&value))
                    .transpose()
                    .map_err(|err| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(err),
                        )
                    })?;
                Ok((
                    row.get::<_, i64>(0)?,
                    OsvFinding {
                        osv_id: row.get(1)?,
                        summary: row.get(2)?,
                        source: row.get(3)?,
                        modified,
                        effective_severity: None,
                        evaluation_error: None,
                    },
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .map_err(sqlite_error)?;

    let mut ranges = Vec::new();
    for row in rows {
        let (range_id, advisory, range_type) = row.map_err(sqlite_error)?;
        ranges.push(StoredRange {
            advisory,
            range_type,
            events: range_events(connection, range_id)?,
        });
    }
    Ok(ranges)
}

fn range_events(connection: &Connection, range_id: i64) -> Result<Vec<RangeEvent>, OsvError> {
    let mut statement = connection
        .prepare(
            r#"
SELECT event_type, version
FROM affected_range_events
WHERE range_id = ?1
ORDER BY event_order
"#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([range_id], |row| {
            Ok(RangeEvent {
                event_type: row.get(0)?,
                version: row.get(1)?,
            })
        })
        .map_err(sqlite_error)?;

    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

fn range_matches_artifact(range: &StoredRange, artifact: &Artifact) -> Result<bool, OsvError> {
    match (artifact.ecosystem.osv_name(), range.range_type.as_str()) {
        ("npm", "SEMVER") => {
            let version = npm_semver::Version::parse(&artifact.version).map_err(|err| {
                range_error(
                    artifact,
                    format!("invalid npm version {}: {err}", artifact.version),
                )
            })?;
            evaluate_range_events(range, artifact, |boundary| {
                compare_npm_version(&version, boundary, artifact)
            })
        }
        ("PyPI", "ECOSYSTEM") => {
            let version = pep440::Version::from_str(&artifact.version).map_err(|err| {
                range_error(
                    artifact,
                    format!("invalid PyPI version {}: {err}", artifact.version),
                )
            })?;
            evaluate_range_events(range, artifact, |boundary| {
                compare_pypi_version(&version, boundary, artifact)
            })
        }
        ("Go", "SEMVER") | ("Go", "ECOSYSTEM") => {
            let version = go::osv_version(&artifact.version)
                .map_err(|err| range_error(artifact, err.to_string()))?;
            evaluate_range_events(range, artifact, |boundary| {
                go::compare_versions(&format!("v{version}"), &format!("v{boundary}"))
                    .map_err(|err| range_error(artifact, err.to_string()))
            })
        }
        ("crates.io", "SEMVER" | "ECOSYSTEM") => {
            let version = cargo_semver::parse(&artifact.version).map_err(|err| {
                range_error(
                    artifact,
                    format!("invalid Cargo version {}: {err}", artifact.version),
                )
            })?;
            evaluate_range_events(range, artifact, |boundary| {
                compare_cargo_version(&version, boundary, artifact)
            })
        }
        ("NuGet", "ECOSYSTEM") => evaluate_range_events(range, artifact, |boundary| {
            compare_nuget_version(&artifact.version, boundary, artifact)
        }),
        (_, range_type) => Err(range_error(
            artifact,
            format!(
                "unsupported range type {range_type} for ecosystem {}",
                artifact.ecosystem.osv_name()
            ),
        )),
    }
}

fn compare_nuget_version(
    version: &str,
    boundary: &str,
    artifact: &Artifact,
) -> Result<Ordering, OsvError> {
    let parse = |value: &str| {
        crate::artifact::normalize_nuget_version(value).map_err(|err| {
            range_error(
                artifact,
                format!("invalid NuGet range boundary {value}: {err}"),
            )
        })
    };
    let version = parse(version)?;
    let boundary = parse(boundary)?;
    let split = |value: &str| {
        let (core, pre) = value
            .split_once('-')
            .map_or((value, None), |parts| (parts.0, Some(parts.1)));
        (
            core.split('.')
                .map(|n| n.parse::<u64>().unwrap_or(0))
                .collect::<Vec<_>>(),
            pre.map(str::to_ascii_lowercase),
        )
    };
    let (left, left_pre) = split(&version);
    let (right, right_pre) = split(&boundary);
    match left.cmp(&right) {
        Ordering::Equal => match (left_pre, right_pre) {
            (None, None) => Ok(Ordering::Equal),
            (None, Some(_)) => Ok(Ordering::Greater),
            (Some(_), None) => Ok(Ordering::Less),
            (Some(a), Some(b)) => Ok(compare_nuget_prerelease(&a, &b)),
        },
        other => Ok(other),
    }
}
fn compare_nuget_prerelease(left: &str, right: &str) -> Ordering {
    for (a, b) in left.split('.').zip(right.split('.')) {
        let order = match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(a), Ok(b)) => a.cmp(&b),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            _ => a.cmp(b),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    left.split('.').count().cmp(&right.split('.').count())
}

fn osv_query_version(artifact: &Artifact) -> String {
    if artifact.ecosystem == Ecosystem::Go {
        go::osv_version(&artifact.version).unwrap_or_else(|_| artifact.version.clone())
    } else {
        artifact.version.clone()
    }
}

fn evaluate_range_events<F>(
    range: &StoredRange,
    artifact: &Artifact,
    mut compare_boundary: F,
) -> Result<bool, OsvError>
where
    F: FnMut(&str) -> Result<Ordering, OsvError>,
{
    let mut affected = false;
    for event in &range.events {
        match event.event_type.as_str() {
            "introduced" => {
                if event.version == "0" || compare_boundary(&event.version)? != Ordering::Less {
                    affected = true;
                }
            }
            "fixed" | "limit" => {
                if affected && compare_boundary(&event.version)? != Ordering::Less {
                    affected = false;
                }
            }
            "last_affected" => {
                if affected {
                    affected = compare_boundary(&event.version)? != Ordering::Greater;
                }
            }
            other => {
                return Err(range_error(
                    artifact,
                    format!("unsupported range event type {other}"),
                ));
            }
        }
    }
    Ok(affected)
}

fn compare_npm_version(
    version: &npm_semver::Version,
    boundary: &str,
    artifact: &Artifact,
) -> Result<Ordering, OsvError> {
    let boundary = npm_semver::Version::parse(boundary).map_err(|err| {
        range_error(
            artifact,
            format!("invalid npm range boundary {boundary}: {err}"),
        )
    })?;
    Ok(version.cmp(&boundary))
}

fn compare_pypi_version(
    version: &pep440::Version,
    boundary: &str,
    artifact: &Artifact,
) -> Result<Ordering, OsvError> {
    let boundary = pep440::Version::from_str(boundary).map_err(|err| {
        range_error(
            artifact,
            format!("invalid PyPI range boundary {boundary}: {err}"),
        )
    })?;
    Ok(version.cmp(&boundary))
}

fn compare_cargo_version(
    version: &cargo_semver,
    boundary: &str,
    artifact: &Artifact,
) -> Result<Ordering, OsvError> {
    let boundary = cargo_semver::parse(boundary).map_err(|err| {
        range_error(
            artifact,
            format!("invalid Cargo range boundary {boundary}: {err}"),
        )
    })?;
    Ok(version.cmp(&boundary))
}

fn range_error(artifact: &Artifact, message: String) -> OsvError {
    OsvError::RangeEvaluation {
        package: artifact.identity(),
        message,
    }
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, OsvError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|err| OsvError::LocalStore(format!("invalid timestamp {value}: {err}")))
}

fn sqlite_error(error: rusqlite::Error) -> OsvError {
    OsvError::LocalStore(error.to_string())
}

#[derive(Debug, Clone, Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct OsvBatchQueryRequest {
    queries: Vec<OsvQueryRequest>,
}

#[derive(Debug, Clone, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchQueryResponse {
    #[serde(default)]
    results: Vec<OsvQueryResponse>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    modified: Option<DateTime<Utc>>,
    withdrawn: Option<DateTime<Utc>>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvLiveAffected>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvLiveAffected {
    package: OsvPackageResponse,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvPackageResponse {
    name: String,
    ecosystem: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, Ecosystem};
    use crate::config::{Config, LocalOsvConfig, LocalOsvStaleBehavior, OsvSource};
    use axum::{
        Json, Router,
        extract::{Path as AxumPath, State},
        routing::{get, post},
    };
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;
    use tempfile::tempdir;
    use zip::{ZipWriter, write::SimpleFileOptions};

    #[derive(Default)]
    struct LiveMockState {
        query_calls: AtomicUsize,
        batch_calls: AtomicUsize,
        active_details: AtomicUsize,
        peak_details: AtomicUsize,
        detail_counts: Mutex<BTreeMap<String, usize>>,
    }

    async fn mock_query(
        State(state): State<Arc<LiveMockState>>,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        state.query_calls.fetch_add(1, AtomicOrdering::SeqCst);
        if body.get("version").and_then(|value| value.as_str()) == Some("single-cycle") {
            return Json(serde_json::json!({"vulns":[],"next_page_token":"cycle"}));
        }
        if body.get("version").and_then(|value| value.as_str()) == Some("withdrawn") {
            return Json(serde_json::json!({"vulns":[{
                "id":"GHSA-withdrawn","modified":"2026-07-11T00:00:00Z",
                "withdrawn":"2026-07-11T01:00:00Z"
            }]}));
        }
        if body.get("version").and_then(|value| value.as_str()) == Some("parity") {
            return Json(serde_json::json!({"vulns": [{
                "id":"GHSA-shared", "modified":"2026-07-11T00:00:00Z",
                "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected":[{"package":{"ecosystem":"npm","name":"demo"}}]
            }]}));
        }
        if body.get("page_token").is_some() {
            Json(serde_json::json!({"vulns": [{
                "id": "GHSA-page-2", "modified": "2026-07-11T00:00:00Z",
                "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{"package":{"ecosystem":"npm","name":"demo"}}]
            }]}))
        } else {
            Json(serde_json::json!({
                "vulns": [{
                    "id": "GHSA-page-1", "modified": "2026-07-11T00:00:00Z",
                    "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                    "affected": [{"package":{"ecosystem":"npm","name":"demo"},"severity":[{"type":"CVSS_V2","score":"AV:A/AC:H/Au:N/C:C/I:C/A:C"}]}]
                }], "next_page_token": "single-next"
            }))
        }
    }

    async fn mock_batch(
        State(state): State<Arc<LiveMockState>>,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        state.batch_calls.fetch_add(1, AtomicOrdering::SeqCst);
        let queries = body["queries"].as_array().unwrap();
        if queries.iter().any(|query| {
            query.get("version").and_then(|value| value.as_str()) == Some("batch-cycle")
        }) {
            return Json(serde_json::json!({"results":[{
                "vulns":[],"next_page_token":"batch-cycle-token"
            }]}));
        }
        if queries
            .iter()
            .any(|query| query.get("page_token").is_some())
        {
            return Json(serde_json::json!({"results":[{"vulns":[{
                "id":"GHSA-extra", "modified":"2026-07-11T00:00:00Z"
            }]}]}));
        }
        let results = queries
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let version = queries[index]
                    .get("version")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                if version == "mal-bad" {
                    return serde_json::json!({"vulns":[
                        {"id":"MAL-2026-known","modified":"2026-07-11T00:00:00Z"},
                        {"id":"GHSA-bad","modified":"2026-07-11T00:00:00Z"}
                    ]});
                }
                if version == "mismatch" {
                    return serde_json::json!({"vulns":[
                        {"id":"GHSA-mismatch","modified":"2026-07-11T00:00:00Z"}
                    ]});
                }
                if version == "withdrawn" {
                    return serde_json::json!({"vulns":[
                        {"id":"GHSA-withdrawn","modified":"2026-07-11T00:00:00Z"}
                    ]});
                }
                let mut vulns = vec![serde_json::json!({
                    "id":"GHSA-shared", "modified":"2026-07-11T00:00:00Z"
                })];
                if index == 0 {
                    vulns.extend((0..18).map(|number| {
                        serde_json::json!({
                            "id": format!("GHSA-unique-{number:02}"),
                            "modified":"2026-07-11T00:00:00Z"
                        })
                    }));
                    serde_json::json!({"vulns":vulns,"next_page_token":"batch-next"})
                } else {
                    serde_json::json!({"vulns":vulns})
                }
            })
            .collect::<Vec<_>>();
        Json(serde_json::json!({"results":results}))
    }

    async fn mock_detail(
        State(state): State<Arc<LiveMockState>>,
        AxumPath(id): AxumPath<String>,
    ) -> Json<serde_json::Value> {
        *state
            .detail_counts
            .lock()
            .unwrap()
            .entry(id.clone())
            .or_default() += 1;
        let active = state.active_details.fetch_add(1, AtomicOrdering::SeqCst) + 1;
        state.peak_details.fetch_max(active, AtomicOrdering::SeqCst);
        tokio::time::sleep(Duration::from_millis(10)).await;
        state.active_details.fetch_sub(1, AtomicOrdering::SeqCst);
        if id == "GHSA-bad" {
            return Json(serde_json::json!({
                "id":id,"modified":"2026-07-11T00:00:00Z",
                "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:BROKEN"}],
                "affected":[{"package":{"ecosystem":"npm","name":"demo"}}]
            }));
        }
        if id == "GHSA-mismatch" {
            return Json(serde_json::json!({
                "id":"GHSA-other","modified":"2026-07-11T00:00:00Z",
                "affected":[{"package":{"ecosystem":"npm","name":"demo"}}]
            }));
        }
        if id == "GHSA-withdrawn" {
            return Json(serde_json::json!({
                "id":id,"modified":"2026-07-11T00:00:00Z",
                "withdrawn":"2026-07-11T01:00:00Z"
            }));
        }
        Json(serde_json::json!({
            "id":id, "modified":"2026-07-11T00:00:00Z",
            "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected":[{"package":{"ecosystem":"npm","name":"demo"}}]
        }))
    }

    async fn live_mock() -> (String, Arc<LiveMockState>) {
        let state = Arc::new(LiveMockState::default());
        let app = Router::new()
            .route("/v1/query", post(mock_query))
            .route("/v1/querybatch", post(mock_batch))
            .route("/v1/vulns/{id}", get(mock_detail))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), state)
    }

    #[tokio::test]
    async fn live_queries_paginate_hydrate_once_bound_concurrency_and_preserve_cardinality() {
        let (url, state) = live_mock().await;
        let client = OsvHttpClient::new(url);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.0.0", None);
        let single = client.check(&artifact).await.unwrap();
        assert_eq!(single.len(), 2);
        assert_eq!(
            single[0].effective_severity.as_ref().unwrap().base_score,
            6.8
        );
        assert_eq!(state.query_calls.load(AtomicOrdering::SeqCst), 2);

        let batch = client
            .check_many(&[artifact.clone(), artifact.clone()])
            .await
            .unwrap();
        assert_eq!(batch.len(), 2);
        assert!(
            batch[0]
                .iter()
                .any(|finding| finding.osv_id == "GHSA-extra")
        );
        assert_eq!(
            state.detail_counts.lock().unwrap().get("GHSA-shared"),
            Some(&1)
        );
        assert_eq!(state.batch_calls.load(AtomicOrdering::SeqCst), 2);
        assert!(state.peak_details.load(AtomicOrdering::SeqCst) > 1);
        assert!(state.peak_details.load(AtomicOrdering::SeqCst) <= OSV_DETAIL_CONCURRENCY);
    }

    #[tokio::test]
    async fn malicious_only_batch_does_not_hydrate_non_malicious_details() {
        let (url, state) = live_mock().await;
        let client = OsvHttpClient::with_vulnerability_policy(url, false);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.0.0", None);
        let findings = client.check_many(&[artifact]).await.unwrap();
        assert!(findings[0].is_empty());
        assert!(state.detail_counts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn live_direct_and_batch_findings_are_equivalent_for_same_advisory() {
        let (url, _) = live_mock().await;
        let client = OsvHttpClient::new(url);
        let direct_artifact = Artifact::package(Ecosystem::Npm, "demo", "parity", None);
        let batch_artifact = Artifact::package(Ecosystem::Npm, "demo", "1.0.0", None);
        let direct = client.check(&direct_artifact).await.unwrap();
        let batch = client.check_many(&[batch_artifact]).await.unwrap();
        let batch_shared = batch[0]
            .iter()
            .find(|finding| finding.osv_id == "GHSA-shared")
            .unwrap();
        assert_eq!(&direct[0], batch_shared);
    }

    #[tokio::test]
    async fn repeated_single_and_batch_page_tokens_fail_without_looping() {
        let (url, _) = live_mock().await;
        let client = OsvHttpClient::new(url);
        let single = Artifact::package(Ecosystem::Npm, "demo", "single-cycle", None);
        assert!(matches!(
            client.check(&single).await.unwrap_err(),
            OsvError::PaginationCycle { .. }
        ));
        let batch = Artifact::package(Ecosystem::Npm, "demo", "batch-cycle", None);
        assert!(matches!(
            client.check_many(&[batch]).await.unwrap_err(),
            OsvError::PaginationCycle { .. }
        ));
    }

    #[tokio::test]
    async fn batch_preserves_known_mal_and_isolates_detail_errors() {
        let (url, _) = live_mock().await;
        let client = OsvHttpClient::new(url);
        let bad = Artifact::package(Ecosystem::Npm, "demo", "mal-bad", None);
        let clean = Artifact::package(Ecosystem::Npm, "demo", "clean", None);
        let results = client.check_many(&[bad.clone(), clean]).await.unwrap();
        assert!(
            results[0]
                .iter()
                .any(|finding| finding.osv_id.starts_with("MAL-"))
        );
        assert!(
            results[0]
                .iter()
                .any(|finding| finding.evaluation_error.is_some())
        );
        assert_eq!(results[1].len(), 1);
        assert!(results[1][0].evaluation_error.is_none());

        let mut config = Config::default();
        config.policy.osv.on_error = crate::config::OsvErrorBehavior::Allow;
        let decision = crate::policy::PolicyEngine::new(&config).evaluate_with_malicious_result(
            &bad,
            Utc::now(),
            Some(Ok(results[0].clone())),
        );
        assert_eq!(decision.reason, crate::policy::DecisionReason::Malicious);
    }

    #[tokio::test]
    async fn mismatched_detail_identity_is_assigned_to_requesting_artifact() {
        let (url, _) = live_mock().await;
        let client = OsvHttpClient::new(url);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "mismatch", None);
        let findings = client.check_many(&[artifact]).await.unwrap();
        assert_eq!(findings[0].len(), 1);
        assert!(
            findings[0][0]
                .evaluation_error
                .as_deref()
                .unwrap()
                .contains("ID mismatch")
        );
    }

    #[tokio::test]
    async fn withdrawn_live_single_and_batch_findings_are_ignored() {
        let (url, _) = live_mock().await;
        let client = OsvHttpClient::new(url);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "withdrawn", None);
        assert!(client.check(&artifact).await.unwrap().is_empty());
        assert!(client.check_many(&[artifact]).await.unwrap()[0].is_empty());
    }

    fn severity(severity_type: &str, vector: &str) -> OsvSeverity {
        OsvSeverity {
            severity_type: severity_type.to_string(),
            vector: vector.to_string(),
        }
    }

    #[test]
    fn effective_severity_supports_cvss_v2_v3_and_v4() {
        let cases = [
            ("CVSS_V2", "AV:A/AC:H/Au:N/C:C/I:C/A:C", 6.8),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                9.8,
            ),
            (
                "CVSS_V4",
                "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H",
                5.2,
            ),
        ];
        for (severity_type, vector, expected) in cases {
            let effective = effective_osv_severity(&[severity(severity_type, vector)], None)
                .unwrap()
                .unwrap();
            assert_eq!(effective.severity_type, severity_type);
            assert_eq!(effective.vector, vector);
            assert_eq!(effective.base_score, expected);
        }
    }

    #[test]
    fn effective_severity_uses_base_with_temporal_environmental_and_threat_metrics() {
        let cases = [
            (
                "CVSS_V2",
                "AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC/CDP:N/TD:N/CR:L/IR:L/AR:L",
                10.0,
            ),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:A",
                9.8,
            ),
            (
                "CVSS_V4",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U",
                9.1,
            ),
        ];
        for (severity_type, raw, expected_base) in cases {
            let vector = raw.parse::<CvssVector>().unwrap();
            if severity_type != "CVSS_V4" {
                assert_ne!(
                    f64::from(polycvss::Score::from(vector)),
                    f64::from(vector.base_score()),
                    "v2/v3 probe vector must distinguish general score from base score"
                );
            } else {
                // polycvss defines the v4 general score as its v4 base score;
                // the explicit accessor still prevents v2/v3 temporal drift.
                assert_eq!(
                    f64::from(polycvss::Score::from(vector)),
                    f64::from(vector.base_score())
                );
            }
            assert_eq!(
                effective_osv_severity(&[severity(severity_type, raw)], None)
                    .unwrap()
                    .unwrap()
                    .base_score,
                expected_base
            );
        }
    }

    #[test]
    fn effective_severity_uses_highest_recognized_vector() {
        let effective = effective_osv_severity(
            &[
                severity("CVSS_V2", "AV:A/AC:H/Au:N/C:C/I:C/A:C"),
                severity("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            ],
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(effective.base_score, 9.8);
        assert_eq!(effective.severity_type, "CVSS_V3");
    }

    #[test]
    fn package_severity_overrides_top_level_and_empty_package_falls_back() {
        let top = [severity(
            "CVSS_V3",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )];
        let package = [severity("CVSS_V2", "AV:A/AC:H/Au:N/C:C/I:C/A:C")];
        assert_eq!(
            effective_osv_severity(&top, Some(&package))
                .unwrap()
                .unwrap()
                .base_score,
            6.8
        );
        assert_eq!(
            effective_osv_severity(&top, Some(&[]))
                .unwrap()
                .unwrap()
                .base_score,
            9.8
        );
    }

    #[test]
    fn schema_valid_package_and_top_level_severity_records_deserialize() {
        let package_advisory: OsvDumpAdvisory = serde_json::from_str(
            r#"{
              "id": "OSV-TEST-1",
              "modified": "2026-07-11T00:00:00Z",
              "affected": [{
                "package": {"ecosystem": "npm", "name": "demo"},
                "severity": [{
                  "type": "CVSS_V2",
                  "score": "AV:A/AC:H/Au:N/C:C/I:C/A:C"
                }],
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
              }]
            }"#,
        )
        .unwrap();

        assert_eq!(
            effective_advisory_severity(&package_advisory, "npm", "demo")
                .unwrap()
                .unwrap()
                .base_score,
            6.8
        );

        let top_advisory: OsvDumpAdvisory = serde_json::from_str(
            r#"{
              "id": "OSV-TEST-2",
              "modified": "2026-07-11T00:00:00Z",
              "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
              }],
              "affected": [{
                "package": {"ecosystem": "npm", "name": "demo"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
              }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            effective_advisory_severity(&top_advisory, "npm", "demo")
                .unwrap()
                .unwrap()
                .base_score,
            9.8
        );
    }

    #[test]
    fn repeated_matching_affected_entries_choose_highest_package_score() {
        let vulnerability: OsvVulnerability = serde_json::from_str(
            r#"{
              "id":"GHSA-repeated","modified":"2026-07-11T00:00:00Z",
              "affected":[
                {"package":{"ecosystem":"npm","name":"demo"},"severity":[{"type":"CVSS_V2","score":"AV:A/AC:H/Au:N/C:C/I:C/A:C"}]},
                {"package":{"ecosystem":"npm","name":"demo"},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
              ]
            }"#,
        )
        .unwrap();
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.0.0", None);
        let finding = finding_from_vulnerability(vulnerability, &artifact)
            .unwrap()
            .unwrap();
        assert_eq!(finding.effective_severity.unwrap().base_score, 9.8);
    }

    #[test]
    fn missing_and_unknown_severity_are_unscored() {
        assert_eq!(effective_osv_severity(&[], None).unwrap(), None);
        assert_eq!(
            effective_osv_severity(&[severity("GHSA", "HIGH")], None).unwrap(),
            None
        );
    }

    #[test]
    fn malformed_recognized_severity_is_an_error() {
        let error =
            effective_osv_severity(&[severity("CVSS_V3", "CVSS:3.1/AV:BROKEN")], None).unwrap_err();
        assert_eq!(error.severity_type, "CVSS_V3");
        assert_eq!(error.vector, "CVSS:3.1/AV:BROKEN");
    }

    #[test]
    fn recognized_severity_rejects_a_mismatched_vector_version() {
        let error = effective_osv_severity(
            &[severity(
                "CVSS_V4",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )],
            None,
        )
        .unwrap_err();
        assert_eq!(error.severity_type, "CVSS_V4");
        assert!(error.message.contains("does not match"));
    }

    #[test]
    fn equal_scores_use_deterministic_type_and_vector_tie_breaks() {
        let a = severity("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        let b = severity(
            "CVSS_V3",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X",
        );
        let forward = effective_osv_severity(&[a.clone(), b.clone()], None)
            .unwrap()
            .unwrap();
        let reverse = effective_osv_severity(&[b, a], None).unwrap().unwrap();
        assert_eq!(forward, reverse);
    }

    #[test]
    fn parses_osv_response_without_vulns_as_empty() {
        let parsed = serde_json::from_str::<OsvQueryResponse>("{}").unwrap();
        assert!(parsed.vulns.is_empty());
    }

    #[test]
    fn parses_osv_response_hits() {
        let parsed = serde_json::from_str::<OsvQueryResponse>(
            r#"{
              "vulns": [
                {
                  "id": "MAL-2026-000001",
                  "summary": "Malicious package",
                  "modified": "2026-07-05T12:00:00Z"
                }
              ]
            }"#,
        )
        .unwrap();
        assert_eq!(parsed.vulns[0].id, "MAL-2026-000001");
        assert_eq!(
            parsed.vulns[0].summary.as_deref(),
            Some("Malicious package")
        );
        assert!(parsed.vulns[0].modified.is_some());
    }

    #[test]
    fn osv_ecosystem_names_match_api_expectations() {
        let npm = Artifact::package(Ecosystem::Npm, "lodash", "4.17.21", None);
        let pypi = Artifact::package(Ecosystem::Pypi, "Requests", "2.32.3", None);
        assert_eq!(npm.ecosystem.osv_name(), "npm");
        assert_eq!(pypi.ecosystem.osv_name(), "PyPI");
        assert_eq!(pypi.name, "requests");
    }

    #[test]
    fn sqlite_schema_initializes_idempotently() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("malicious.sqlite");

        SqliteMaliciousChecker::initialize(&db).unwrap();
        SqliteMaliciousChecker::initialize(&db).unwrap();

        let connection = Connection::open(&db).unwrap();
        let table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'advisories'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 1);
    }

    #[tokio::test]
    async fn sqlite_checker_returns_exact_version_hits() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "npm");
        insert_exact_advisory(
            &connection,
            "MAL-2026-000001",
            "npm",
            "demo",
            "1.2.3",
            Some("Malicious package"),
        );
        let checker = checker_for(&db);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None);

        let hits = checker.check(&artifact).await.unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].osv_id, "MAL-2026-000001");
        assert_eq!(hits[0].summary.as_deref(), Some("Malicious package"));
        assert_eq!(hits[0].source, "osv");
    }

    #[tokio::test]
    async fn sqlite_checker_errors_for_missing_database() {
        let dir = tempdir().unwrap();
        let checker = checker_for(&dir.path().join("missing.sqlite"));
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None);

        let err = checker.check(&artifact).await.unwrap_err();

        assert!(err.to_string().contains("local malicious store failed"));
    }

    #[tokio::test]
    async fn sqlite_checker_errors_for_stale_database_by_default() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_sync_state(&connection, "npm", "healthy", "2020-01-01T00:00:00Z");
        let checker = checker_for(&db);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None);

        let err = checker.check(&artifact).await.unwrap_err();

        assert!(err.to_string().contains("stale"));
    }

    #[tokio::test]
    async fn sqlite_checker_allows_stale_database_when_configured() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_sync_state(&connection, "npm", "healthy", "2020-01-01T00:00:00Z");
        insert_exact_advisory(
            &connection,
            "MAL-2026-000001",
            "npm",
            "demo",
            "1.2.3",
            Some("stale but allowed"),
        );
        let checker = checker_for_with_stale_behavior(&db, LocalOsvStaleBehavior::Allow);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None);

        let hits = checker.check(&artifact).await.unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].osv_id, "MAL-2026-000001");
    }

    #[tokio::test]
    async fn sqlite_checker_errors_for_unhealthy_sync_state() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_sync_state(&connection, "npm", "failed", &Utc::now().to_rfc3339());
        let checker = checker_for(&db);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None);

        let err = checker.check(&artifact).await.unwrap_err();

        assert!(err.to_string().contains("is failed"));
    }

    #[tokio::test]
    async fn configured_checker_uses_sqlite_for_local_source() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "npm");
        insert_exact_advisory(
            &connection,
            "MAL-2026-000099",
            "npm",
            "demo",
            "1.2.3",
            Some("local factory hit"),
        );
        let mut config = Config::default();
        config.policy.osv.source = OsvSource::Local;
        config.policy.osv.api_url = "http://127.0.0.1:9".to_string();
        config.policy.osv.local.sqlite_path = db;
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None);

        let hits = configured_osv_checker(&config)
            .check(&artifact)
            .await
            .unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].osv_id, "MAL-2026-000099");
    }

    #[tokio::test]
    async fn sqlite_checker_preserves_check_many_order() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "npm");
        insert_healthy_sync_state(&connection, "PyPI");
        insert_exact_advisory(
            &connection,
            "MAL-2026-000001",
            "npm",
            "demo",
            "1.2.3",
            Some("npm hit"),
        );
        insert_exact_advisory(
            &connection,
            "MAL-2026-000002",
            "PyPI",
            "requests",
            "2.32.3",
            Some("pypi hit"),
        );
        let checker = checker_for(&db);
        let artifacts = vec![
            Artifact::package(Ecosystem::Npm, "clean", "1.0.0", None),
            Artifact::package(Ecosystem::Pypi, "Requests", "2.32.3", None),
            Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None),
            Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None),
            Artifact::package(Ecosystem::Pypi, "requests", "2.32.3", None),
        ];

        let results = checker.check_many(&artifacts).await.unwrap();

        assert!(results[0].is_empty());
        assert_eq!(results[1][0].osv_id, "MAL-2026-000002");
        assert_eq!(results[2][0].osv_id, "MAL-2026-000001");
        assert_eq!(results[3], results[2]);
        assert_eq!(results[4], results[1]);
    }

    #[tokio::test]
    async fn sqlite_checker_reads_existing_snapshot_during_active_write_transaction() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "npm");
        insert_exact_advisory(
            &connection,
            "MAL-2026-000001",
            "npm",
            "demo",
            "1.2.3",
            Some("existing snapshot hit"),
        );
        let mut writer = open_read_write_connection(&db).unwrap();
        let transaction = writer.transaction().unwrap();
        transaction
            .execute(
                r#"
INSERT INTO advisories (
    osv_id,
    summary,
    modified,
    published,
    withdrawn,
    raw_json,
    source,
    imported_at
) VALUES (
    'MAL-2026-000002',
    'uncommitted advisory',
    '2026-07-01T00:00:00Z',
    NULL,
    NULL,
    '{}',
    'test',
    '2026-07-01T00:00:00Z'
)
"#,
                [],
            )
            .unwrap();
        let checker = checker_for(&db);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None);

        let hits = tokio::time::timeout(Duration::from_millis(500), checker.check(&artifact))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].osv_id, "MAL-2026-000001");
        drop(transaction);
    }

    #[tokio::test]
    async fn sqlite_checker_matches_npm_introduced_zero_range() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "npm");
        insert_range_advisory_with_events(
            &connection,
            "MAL-2026-000001",
            "npm",
            "demo",
            "SEMVER",
            &[("introduced", "0")],
        );
        let checker = checker_for(&db);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None);

        let hits = checker.check(&artifact).await.unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].osv_id, "MAL-2026-000001");
    }

    #[tokio::test]
    async fn sqlite_checker_handles_npm_fixed_boundaries() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "npm");
        insert_range_advisory_with_events(
            &connection,
            "MAL-2026-000001",
            "npm",
            "demo",
            "SEMVER",
            &[("introduced", "1.0.0"), ("fixed", "2.0.0")],
        );
        let checker = checker_for(&db);

        assert!(
            checker
                .check(&Artifact::package(Ecosystem::Npm, "demo", "0.9.9", None))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            checker
                .check(&Artifact::package(Ecosystem::Npm, "demo", "1.5.0", None))
                .await
                .unwrap()[0]
                .osv_id,
            "MAL-2026-000001"
        );
        assert!(
            checker
                .check(&Artifact::package(Ecosystem::Npm, "demo", "2.0.0", None))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn sqlite_checker_handles_fixed_reopening_intervals() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "npm");
        insert_range_advisory_with_events(
            &connection,
            "MAL-2026-000001",
            "npm",
            "demo",
            "SEMVER",
            &[
                ("introduced", "1.0.0"),
                ("fixed", "2.0.0"),
                ("introduced", "3.0.0"),
                ("fixed", "4.0.0"),
            ],
        );
        let checker = checker_for(&db);

        assert!(
            checker
                .check(&Artifact::package(Ecosystem::Npm, "demo", "2.5.0", None))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            checker
                .check(&Artifact::package(Ecosystem::Npm, "demo", "3.5.0", None))
                .await
                .unwrap()[0]
                .osv_id,
            "MAL-2026-000001"
        );
    }

    #[tokio::test]
    async fn sqlite_checker_handles_pypi_last_affected() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "PyPI");
        insert_range_advisory_with_events(
            &connection,
            "MAL-2026-000001",
            "PyPI",
            "demo",
            "ECOSYSTEM",
            &[("introduced", "1.0"), ("last_affected", "1.5")],
        );
        let checker = checker_for(&db);

        assert_eq!(
            checker
                .check(&Artifact::package(Ecosystem::Pypi, "demo", "1.5", None))
                .await
                .unwrap()[0]
                .osv_id,
            "MAL-2026-000001"
        );
        assert!(
            checker
                .check(&Artifact::package(Ecosystem::Pypi, "demo", "1.5.1", None))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn sqlite_checker_handles_pypi_limit() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "PyPI");
        insert_range_advisory_with_events(
            &connection,
            "MAL-2026-000001",
            "PyPI",
            "demo",
            "ECOSYSTEM",
            &[("introduced", "1.0"), ("limit", "2.0")],
        );
        let checker = checker_for(&db);

        assert_eq!(
            checker
                .check(&Artifact::package(Ecosystem::Pypi, "demo", "1.9", None))
                .await
                .unwrap()[0]
                .osv_id,
            "MAL-2026-000001"
        );
        assert!(
            checker
                .check(&Artifact::package(Ecosystem::Pypi, "demo", "2.0", None))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn sqlite_checker_errors_for_unsupported_range_type() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "npm");
        insert_range_advisory_with_events(
            &connection,
            "MAL-2026-000001",
            "npm",
            "demo",
            "GIT",
            &[("introduced", "1.0.0")],
        );
        let checker = checker_for(&db);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "1.2.3", None);

        let err = checker.check(&artifact).await.unwrap_err();

        assert!(matches!(err, OsvError::RangeEvaluation { .. }));
        assert!(err.to_string().contains("unsupported range type GIT"));
    }

    #[tokio::test]
    async fn sqlite_checker_errors_for_unevaluable_version() {
        let dir = tempdir().unwrap();
        let db = initialized_db(dir.path());
        let connection = Connection::open(&db).unwrap();
        insert_healthy_sync_state(&connection, "npm");
        insert_range_advisory_with_events(
            &connection,
            "MAL-2026-000001",
            "npm",
            "demo",
            "SEMVER",
            &[("introduced", "1.0.0")],
        );
        let checker = checker_for(&db);
        let artifact = Artifact::package(Ecosystem::Npm, "demo", "not-a-version", None);

        let err = checker.check(&artifact).await.unwrap_err();

        assert!(matches!(err, OsvError::RangeEvaluation { .. }));
        assert!(err.to_string().contains("invalid npm version"));
    }

    #[tokio::test]
    async fn sync_bootstrap_imports_only_malicious_exact_and_range_records() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("malicious.sqlite");
        let config = local_config_for(&db);
        let npm_exact_and_range =
            include_bytes!("../tests/fixtures/osv/npm-mal-exact-and-range.json");
        let npm_non_mal = br#"{
            "id": "GHSA-xxxx-yyyy-zzzz",
            "modified": "2026-07-01T00:00:00Z",
            "affected": [{
                "package": { "name": "clean", "ecosystem": "npm" },
                "versions": ["9.9.9"]
            }]
        }"#;
        let pypi_exact = include_bytes!("../tests/fixtures/osv/pypi-mal-exact.json");
        let client = FixtureDumpClient::new([
            (
                all_zip_url(Ecosystem::Npm),
                zip_bytes([
                    ("MAL-2022-1122.json", npm_exact_and_range.as_slice()),
                    ("GHSA-xxxx-yyyy-zzzz.json", npm_non_mal.as_slice()),
                ]),
            ),
            (
                all_zip_url(Ecosystem::Pypi),
                zip_bytes([("MAL-2023-10.json", pypi_exact.as_slice())]),
            ),
            (all_zip_url(Ecosystem::CratesIo), zip_bytes([])),
        ]);

        let report = sync_malicious(&config, &client).await.unwrap();

        assert_eq!(report.ecosystems[0].mode, MaliciousSyncMode::Bootstrap);
        assert_eq!(report.ecosystems[0].imported, 1);
        assert_eq!(report.ecosystems[0].skipped_non_malicious, 1);
        let checker = checker_for(&db);
        let exact_hits = checker
            .check(&Artifact::package(
                Ecosystem::Npm,
                "arpan-package",
                "2.0.5",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(exact_hits[0].osv_id, "MAL-2022-1122");
        let range_hits = checker
            .check(&Artifact::package(
                Ecosystem::Npm,
                "arpan-package",
                "3.0.0",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(range_hits[0].osv_id, "MAL-2022-1122");
        let clean_hits = checker
            .check(&Artifact::package(Ecosystem::Npm, "clean", "9.9.9", None))
            .await
            .unwrap();
        assert!(clean_hits.is_empty());
        let connection = Connection::open(&db).unwrap();
        let raw_json: String = connection
            .query_row(
                "SELECT raw_json FROM advisories WHERE osv_id = 'MAL-2022-1122'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_json, "{}");
    }

    #[tokio::test]
    async fn sync_retains_raw_advisory_json_when_configured() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("malicious.sqlite");
        let mut config = local_config_for(&db);
        config.retain_raw_advisories = true;
        let npm_exact_and_range =
            include_bytes!("../tests/fixtures/osv/npm-mal-exact-and-range.json");
        let client = FixtureDumpClient::new([
            (
                all_zip_url(Ecosystem::Npm),
                zip_bytes([("MAL-2022-1122.json", npm_exact_and_range.as_slice())]),
            ),
            (all_zip_url(Ecosystem::Pypi), zip_bytes([])),
            (all_zip_url(Ecosystem::CratesIo), zip_bytes([])),
        ]);

        sync_malicious(&config, &client).await.unwrap();

        let connection = Connection::open(&db).unwrap();
        let raw_json: String = connection
            .query_row(
                "SELECT raw_json FROM advisories WHERE osv_id = 'MAL-2022-1122'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(raw_json.contains("arpan-package"));
    }

    #[tokio::test]
    async fn sync_incremental_replaces_existing_advisory_rows() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("malicious.sqlite");
        let config = local_config_for(&db);
        let first = advisory_json(
            "MAL-2026-000001",
            "npm",
            "demo",
            &["1.0.0"],
            r#""ranges":[]"#,
            None,
        );
        let second = advisory_json(
            "MAL-2026-000001",
            "npm",
            "demo",
            &["2.0.0"],
            r#""ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.0"}]}]"#,
            None,
        );
        let client = FixtureDumpClient::new([
            (
                all_zip_url(Ecosystem::Npm),
                zip_bytes([("MAL-2026-000001.json", first.as_slice())]),
            ),
            (all_zip_url(Ecosystem::Pypi), zip_bytes([])),
            (all_zip_url(Ecosystem::CratesIo), zip_bytes([])),
            (
                modified_id_csv_url(Ecosystem::Npm),
                b"2099-01-01T00:00:00Z,MAL-2026-000001\n".to_vec(),
            ),
            (modified_id_csv_url(Ecosystem::Pypi), Vec::new()),
            (modified_id_csv_url(Ecosystem::CratesIo), Vec::new()),
            (advisory_json_url(Ecosystem::Npm, "MAL-2026-000001"), second),
        ]);
        sync_malicious(&config, &client).await.unwrap();

        let report = sync_malicious(&config, &client).await.unwrap();

        assert_eq!(report.ecosystems[0].mode, MaliciousSyncMode::Incremental);
        let checker = checker_for(&db);
        assert!(
            checker
                .check(&Artifact::package(Ecosystem::Npm, "demo", "1.0.0", None))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            checker
                .check(&Artifact::package(Ecosystem::Npm, "demo", "2.5.0", None))
                .await
                .unwrap()[0]
                .osv_id,
            "MAL-2026-000001"
        );
    }

    #[tokio::test]
    async fn sync_withdrawn_advisory_no_longer_blocks() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("malicious.sqlite");
        let config = local_config_for(&db);
        let active = advisory_json(
            "MAL-2026-000001",
            "npm",
            "demo",
            &["1.0.0"],
            r#""ranges":[]"#,
            None,
        );
        let withdrawn = advisory_json(
            "MAL-2026-000001",
            "npm",
            "demo",
            &["1.0.0"],
            r#""ranges":[]"#,
            Some("2026-07-08T00:00:00Z"),
        );
        let client = FixtureDumpClient::new([
            (
                all_zip_url(Ecosystem::Npm),
                zip_bytes([("MAL-2026-000001.json", active.as_slice())]),
            ),
            (all_zip_url(Ecosystem::Pypi), zip_bytes([])),
            (all_zip_url(Ecosystem::CratesIo), zip_bytes([])),
            (
                modified_id_csv_url(Ecosystem::Npm),
                b"2099-01-01T00:00:00Z,MAL-2026-000001\n".to_vec(),
            ),
            (modified_id_csv_url(Ecosystem::Pypi), Vec::new()),
            (modified_id_csv_url(Ecosystem::CratesIo), Vec::new()),
            (
                advisory_json_url(Ecosystem::Npm, "MAL-2026-000001"),
                withdrawn,
            ),
        ]);
        sync_malicious(&config, &client).await.unwrap();
        sync_malicious(&config, &client).await.unwrap();
        let checker = checker_for(&db);

        let hits = checker
            .check(&Artifact::package(Ecosystem::Npm, "demo", "1.0.0", None))
            .await
            .unwrap();

        assert!(hits.is_empty());
    }

    #[tokio::test]
    async fn failed_incremental_sync_preserves_previous_good_snapshot() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("malicious.sqlite");
        let config = local_config_for(&db);
        let active = advisory_json(
            "MAL-2026-000001",
            "npm",
            "demo",
            &["1.0.0"],
            r#""ranges":[]"#,
            None,
        );
        let client = FixtureDumpClient::new([
            (
                all_zip_url(Ecosystem::Npm),
                zip_bytes([("MAL-2026-000001.json", active.as_slice())]),
            ),
            (all_zip_url(Ecosystem::Pypi), zip_bytes([])),
            (all_zip_url(Ecosystem::CratesIo), zip_bytes([])),
            (
                modified_id_csv_url(Ecosystem::Npm),
                b"2099-01-01T00:00:00Z,MAL-2026-999999\n".to_vec(),
            ),
            (modified_id_csv_url(Ecosystem::Pypi), Vec::new()),
            (modified_id_csv_url(Ecosystem::CratesIo), Vec::new()),
        ]);
        sync_malicious(&config, &client).await.unwrap();

        let err = sync_malicious(&config, &client).await.unwrap_err();

        assert!(err.to_string().contains("missing fixture response"));
        let checker = checker_for(&db);
        let hits = checker
            .check(&Artifact::package(Ecosystem::Npm, "demo", "1.0.0", None))
            .await
            .unwrap();
        assert_eq!(hits[0].osv_id, "MAL-2026-000001");
        let connection = Connection::open(&db).unwrap();
        let (status, error_summary): (String, Option<String>) = connection
            .query_row(
                "SELECT status, error_summary FROM sync_state WHERE ecosystem = 'npm'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "healthy");
        assert!(error_summary.unwrap().contains("missing fixture response"));
    }

    #[test]
    fn modified_id_csv_compares_fractional_timestamps_chronologically() {
        let rows = parse_modified_id_csv(
            b"2026-07-07T17:16:49Z,MAL-2026-000001\n2026-07-07T17:16:49.1Z,MAL-2026-000002\n",
            Some("2026-07-07T17:16:49Z"),
        )
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].osv_id, "MAL-2026-000002");
        assert_eq!(
            serialize_high_watermark(rows[0].modified_at),
            "2026-07-07T17:16:49.100000000Z"
        );
    }

    struct FixtureDumpClient {
        responses: BTreeMap<String, Vec<u8>>,
    }

    impl FixtureDumpClient {
        fn new<const N: usize>(responses: [(String, Vec<u8>); N]) -> Self {
            Self {
                responses: responses.into_iter().collect(),
            }
        }
    }

    #[async_trait]
    impl OsvDumpClient for FixtureDumpClient {
        async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, OsvError> {
            if let Some(response) = self.responses.get(url) {
                return Ok(response.clone());
            }
            // Go was added after the existing npm/PyPI fixtures. Empty Go
            // snapshots keep those fixtures focused while exercising its
            // independent local-sync state machine.
            if url.contains("/Go/all.zip") {
                return Ok(zip_bytes([]));
            }
            if url.contains("/Go/modified_id.csv") {
                return Ok(Vec::new());
            }
            if url.contains("/NuGet/all.zip") {
                return Ok(zip_bytes([]));
            }
            if url.contains("/NuGet/modified_id.csv") {
                return Ok(Vec::new());
            }
            Err(OsvError::Sync(format!(
                "missing fixture response for {url}"
            )))
        }
    }

    fn zip_bytes<const N: usize>(entries: [(&str, &[u8]); N]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (name, bytes) in entries {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn advisory_json(
        id: &str,
        ecosystem: &str,
        name: &str,
        versions: &[&str],
        ranges_json: &str,
        withdrawn: Option<&str>,
    ) -> Vec<u8> {
        let versions = versions
            .iter()
            .map(|version| format!(r#""{version}""#))
            .collect::<Vec<_>>()
            .join(",");
        let withdrawn = withdrawn
            .map(|value| format!(r#","withdrawn":"{value}""#))
            .unwrap_or_default();
        format!(
            r#"{{
                "schema_version": "1.7.3",
                "id": "{id}",
                "published": "2026-07-01T00:00:00Z",
                "modified": "2026-07-02T00:00:00Z"{withdrawn},
                "summary": "Malicious code in {name}",
                "affected": [{{
                    "package": {{ "name": "{name}", "ecosystem": "{ecosystem}" }},
                    "versions": [{versions}],
                    {ranges_json}
                }}]
            }}"#
        )
        .into_bytes()
    }

    fn local_config_for(path: &Path) -> LocalOsvConfig {
        LocalOsvConfig {
            sqlite_path: path.to_path_buf(),
            max_staleness: Duration::from_secs(24 * 60 * 60),
            on_stale: LocalOsvStaleBehavior::Block,
            retain_raw_advisories: false,
            background_sync: false,
            sync_interval: Duration::from_secs(60 * 60),
        }
    }

    fn initialized_db(dir: &Path) -> std::path::PathBuf {
        let db = dir.join("malicious.sqlite");
        SqliteMaliciousChecker::initialize(&db).unwrap();
        db
    }

    fn checker_for(path: &Path) -> SqliteMaliciousChecker {
        checker_for_with_stale_behavior(path, LocalOsvStaleBehavior::Block)
    }

    fn checker_for_with_stale_behavior(
        path: &Path,
        on_stale: LocalOsvStaleBehavior,
    ) -> SqliteMaliciousChecker {
        SqliteMaliciousChecker::new(&LocalOsvConfig {
            on_stale,
            ..local_config_for(path)
        })
    }

    fn insert_healthy_sync_state(connection: &Connection, ecosystem: &str) {
        insert_sync_state(connection, ecosystem, "healthy", &Utc::now().to_rfc3339());
    }

    fn insert_sync_state(
        connection: &Connection,
        ecosystem: &str,
        status: &str,
        last_success_at: &str,
    ) {
        connection
            .execute(
                r#"
INSERT OR REPLACE INTO sync_state (
    ecosystem,
    source,
    high_watermark,
    last_success_at,
    last_attempted_at,
    status,
    error_summary
) VALUES (?1, 'test', NULL, ?2, ?2, ?3, NULL)
"#,
                params![ecosystem, last_success_at, status],
            )
            .unwrap();
    }

    fn insert_exact_advisory(
        connection: &Connection,
        osv_id: &str,
        ecosystem: &str,
        name: &str,
        version: &str,
        summary: Option<&str>,
    ) {
        insert_advisory(connection, osv_id, summary);
        connection
            .execute(
                "INSERT INTO affected_packages (osv_id, ecosystem, name) VALUES (?1, ?2, ?3)",
                params![osv_id, ecosystem, name],
            )
            .unwrap();
        let package_id = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO affected_versions (affected_package_id, version) VALUES (?1, ?2)",
                params![package_id, version],
            )
            .unwrap();
    }

    fn insert_range_advisory_with_events(
        connection: &Connection,
        osv_id: &str,
        ecosystem: &str,
        name: &str,
        range_type: &str,
        events: &[(&str, &str)],
    ) {
        insert_advisory(connection, osv_id, Some("Range package"));
        connection
            .execute(
                "INSERT INTO affected_packages (osv_id, ecosystem, name) VALUES (?1, ?2, ?3)",
                params![osv_id, ecosystem, name],
            )
            .unwrap();
        let package_id = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO affected_ranges (affected_package_id, range_type) VALUES (?1, ?2)",
                params![package_id, range_type],
            )
            .unwrap();
        let range_id = connection.last_insert_rowid();
        for (index, (event_type, version)) in events.iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO affected_range_events (range_id, event_order, event_type, version) VALUES (?1, ?2, ?3, ?4)",
                    params![range_id, index as i64, event_type, version],
                )
                .unwrap();
        }
    }

    fn insert_advisory(connection: &Connection, osv_id: &str, summary: Option<&str>) {
        connection
            .execute(
                r#"
INSERT INTO advisories (
    osv_id,
    summary,
    modified,
    published,
    withdrawn,
    raw_json,
    source,
    imported_at
) VALUES (?1, ?2, '2026-07-05T12:00:00Z', NULL, NULL, '{}', 'osv', ?3)
"#,
                params![osv_id, summary, Utc::now().to_rfc3339()],
            )
            .unwrap();
    }
}
