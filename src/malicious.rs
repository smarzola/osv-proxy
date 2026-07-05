use crate::artifact::Artifact;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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
}
