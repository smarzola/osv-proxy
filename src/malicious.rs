use crate::artifact::Artifact;
use crate::config::{LocalOsvConfig, LocalOsvStaleBehavior};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use node_semver as npm_semver;
use pep440_rs as pep440;
use reqwest::Client;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[async_trait]
pub trait MaliciousChecker: Send + Sync {
    async fn check(&self, artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError>;

    async fn check_many(
        &self,
        artifacts: &[Artifact],
    ) -> Result<Vec<Vec<MaliciousHit>>, MaliciousError> {
        let mut results = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            results.push(self.check(artifact).await?);
        }
        Ok(results)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaliciousHit {
    pub osv_id: String,
    pub summary: Option<String>,
    pub source: String,
    pub modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
pub enum MaliciousError {
    #[error("OSV request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("OSV batch response returned {actual} results for {expected} queries")]
    InvalidBatchResponse { expected: usize, actual: usize },
    #[error("local malicious store failed: {0}")]
    LocalStore(String),
    #[error("local malicious store could not evaluate range for {package}: {message}")]
    RangeEvaluation { package: String, message: String },
}

#[derive(Debug, Clone)]
pub struct OsvHttpClient {
    api_url: String,
    client: Client,
}

impl OsvHttpClient {
    pub fn new(api_url: impl Into<String>) -> Self {
        Self {
            api_url: api_url.into().trim_end_matches('/').to_string(),
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("OSV HTTP client should build with static timeout configuration"),
        }
    }
}

#[async_trait]
impl MaliciousChecker for OsvHttpClient {
    async fn check(&self, artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
        let url = format!("{}/v1/query", self.api_url);
        let response = self
            .client
            .post(url)
            .json(&OsvQueryRequest {
                package: OsvPackage {
                    name: &artifact.name,
                    ecosystem: artifact.ecosystem.osv_name(),
                },
                version: &artifact.version,
            })
            .send()
            .await?
            .error_for_status()?
            .json::<OsvQueryResponse>()
            .await?;

        Ok(hits_from_vulns(response.vulns))
    }

    async fn check_many(
        &self,
        artifacts: &[Artifact],
    ) -> Result<Vec<Vec<MaliciousHit>>, MaliciousError> {
        if artifacts.is_empty() {
            return Ok(Vec::new());
        }

        let url = format!("{}/v1/querybatch", self.api_url);
        let queries = artifacts
            .iter()
            .map(|artifact| OsvQueryRequest {
                package: OsvPackage {
                    name: &artifact.name,
                    ecosystem: artifact.ecosystem.osv_name(),
                },
                version: &artifact.version,
            })
            .collect::<Vec<_>>();
        let response = self
            .client
            .post(url)
            .json(&OsvBatchQueryRequest { queries })
            .send()
            .await?
            .error_for_status()?
            .json::<OsvBatchQueryResponse>()
            .await?;

        if response.results.len() != artifacts.len() {
            return Err(MaliciousError::InvalidBatchResponse {
                expected: artifacts.len(),
                actual: response.results.len(),
            });
        }

        Ok(response
            .results
            .into_iter()
            .map(|result| hits_from_vulns(result.vulns))
            .collect())
    }
}

fn hits_from_vulns(vulns: Vec<OsvVulnerability>) -> Vec<MaliciousHit> {
    vulns
        .into_iter()
        .map(|vuln| MaliciousHit {
            osv_id: vuln.id,
            summary: vuln.summary,
            source: "osv".to_string(),
            modified: vuln.modified,
        })
        .collect()
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

    pub fn initialize(path: impl AsRef<Path>) -> Result<(), MaliciousError> {
        let mut connection = open_read_write_connection(path.as_ref())?;
        initialize_schema(&mut connection)
    }

    fn open_read_only(&self) -> Result<Connection, MaliciousError> {
        open_read_only_connection(&self.path)
    }

    fn check_with_connection(
        &self,
        connection: &Connection,
        artifact: &Artifact,
    ) -> Result<Vec<MaliciousHit>, MaliciousError> {
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
    ) -> Result<Vec<Vec<MaliciousHit>>, MaliciousError> {
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

        let mut range_results = BTreeMap::<(String, String, String), Vec<MaliciousHit>>::new();
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
impl MaliciousChecker for SqliteMaliciousChecker {
    async fn check(&self, artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
        let connection = self.open_read_only()?;
        self.check_with_connection(&connection, artifact)
    }

    async fn check_many(
        &self,
        artifacts: &[Artifact],
    ) -> Result<Vec<Vec<MaliciousHit>>, MaliciousError> {
        if artifacts.is_empty() {
            return Ok(Vec::new());
        }
        let connection = self.open_read_only()?;
        self.check_many_with_connection(&connection, artifacts)
    }
}

fn open_read_write_connection(path: &Path) -> Result<Connection, MaliciousError> {
    let connection = Connection::open(path).map_err(sqlite_error)?;
    configure_connection(&connection)?;
    Ok(connection)
}

fn open_read_only_connection(path: &Path) -> Result<Connection, MaliciousError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite_error)?;
    configure_connection(&connection)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection) -> Result<(), MaliciousError> {
    connection
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(sqlite_error)?;
    Ok(())
}

fn initialize_schema(connection: &mut Connection) -> Result<(), MaliciousError> {
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
) -> Result<(), MaliciousError> {
    let state = connection
        .query_row(
            "SELECT last_success_at, status FROM sync_state WHERE ecosystem = ?1",
            [ecosystem],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| {
            MaliciousError::LocalStore(format!("missing sync_state row for ecosystem {ecosystem}"))
        })?;

    let (last_success_at, status) = state;
    if status != "healthy" {
        return Err(MaliciousError::LocalStore(format!(
            "sync_state for ecosystem {ecosystem} is {status}"
        )));
    }
    let last_success_at = last_success_at.ok_or_else(|| {
        MaliciousError::LocalStore(format!(
            "sync_state for ecosystem {ecosystem} is missing last_success_at"
        ))
    })?;
    let last_success_at = parse_timestamp(&last_success_at)?;
    let age = Utc::now()
        .signed_duration_since(last_success_at)
        .to_std()
        .map_err(|_| {
            MaliciousError::LocalStore(format!(
                "sync_state for ecosystem {ecosystem} has a future last_success_at"
            ))
        })?;
    if age > checker.max_staleness && checker.on_stale == LocalOsvStaleBehavior::Block {
        return Err(MaliciousError::LocalStore(format!(
            "local malicious data for ecosystem {ecosystem} is stale"
        )));
    }
    Ok(())
}

fn exact_hits(
    connection: &Connection,
    artifact: &Artifact,
) -> Result<Vec<MaliciousHit>, MaliciousError> {
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
                artifact.version
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
                Ok(MaliciousHit {
                    osv_id: row.get(0)?,
                    summary: row.get(1)?,
                    source: row.get(2)?,
                    modified,
                })
            },
        )
        .map_err(sqlite_error)?;

    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

#[derive(Debug, Clone)]
struct StoredRange {
    advisory: MaliciousHit,
    range_type: String,
    events: Vec<RangeEvent>,
}

#[derive(Debug, Clone)]
struct RangeEvent {
    event_type: String,
    version: String,
}

fn range_hits(
    connection: &Connection,
    artifact: &Artifact,
) -> Result<Vec<MaliciousHit>, MaliciousError> {
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
) -> Result<Vec<StoredRange>, MaliciousError> {
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
                    MaliciousHit {
                        osv_id: row.get(1)?,
                        summary: row.get(2)?,
                        source: row.get(3)?,
                        modified,
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

fn range_events(connection: &Connection, range_id: i64) -> Result<Vec<RangeEvent>, MaliciousError> {
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

fn range_matches_artifact(
    range: &StoredRange,
    artifact: &Artifact,
) -> Result<bool, MaliciousError> {
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
        (_, range_type) => Err(range_error(
            artifact,
            format!(
                "unsupported range type {range_type} for ecosystem {}",
                artifact.ecosystem.osv_name()
            ),
        )),
    }
}

fn evaluate_range_events<F>(
    range: &StoredRange,
    artifact: &Artifact,
    mut compare_boundary: F,
) -> Result<bool, MaliciousError>
where
    F: FnMut(&str) -> Result<Ordering, MaliciousError>,
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
) -> Result<Ordering, MaliciousError> {
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
) -> Result<Ordering, MaliciousError> {
    let boundary = pep440::Version::from_str(boundary).map_err(|err| {
        range_error(
            artifact,
            format!("invalid PyPI range boundary {boundary}: {err}"),
        )
    })?;
    Ok(version.cmp(&boundary))
}

fn range_error(artifact: &Artifact, message: String) -> MaliciousError {
    MaliciousError::RangeEvaluation {
        package: artifact.identity(),
        message,
    }
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, MaliciousError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|err| MaliciousError::LocalStore(format!("invalid timestamp {value}: {err}")))
}

fn sqlite_error(error: rusqlite::Error) -> MaliciousError {
    MaliciousError::LocalStore(error.to_string())
}

#[derive(Debug, Serialize)]
struct OsvQueryRequest<'a> {
    package: OsvPackage<'a>,
    version: &'a str,
}

#[derive(Debug, Serialize)]
struct OsvBatchQueryRequest<'a> {
    queries: Vec<OsvQueryRequest<'a>>,
}

#[derive(Debug, Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchQueryResponse {
    #[serde(default)]
    results: Vec<OsvQueryResponse>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    modified: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, Ecosystem};
    use crate::config::{LocalOsvConfig, LocalOsvStaleBehavior};
    use std::path::Path;
    use std::time::Duration;
    use tempfile::tempdir;

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

        assert!(matches!(err, MaliciousError::RangeEvaluation { .. }));
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

        assert!(matches!(err, MaliciousError::RangeEvaluation { .. }));
        assert!(err.to_string().contains("invalid npm version"));
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
            sqlite_path: path.to_path_buf(),
            max_staleness: Duration::from_secs(24 * 60 * 60),
            on_stale,
            background_sync: false,
            sync_interval: Duration::from_secs(60 * 60),
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
