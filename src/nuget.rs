use crate::artifact::{Artifact, Ecosystem, normalize_nuget_name, normalize_nuget_version};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct NugetClient {
    service_index_url: String,
    client: Client,
}

impl NugetClient {
    pub fn new(service_index_url: impl Into<String>) -> Self {
        Self {
            service_index_url: service_index_url.into(),
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("NuGet HTTP client should build"),
        }
    }
}

#[async_trait]
pub trait NugetProvider: Send + Sync {
    async fn fetch_service_index(&self) -> Result<Value, NugetError>;
    async fn fetch_json(&self, url: &str) -> Result<Value, NugetError>;
}

#[async_trait]
impl NugetProvider for NugetClient {
    async fn fetch_service_index(&self) -> Result<Value, NugetError> {
        self.fetch_json(&self.service_index_url).await
    }
    async fn fetch_json(&self, url: &str) -> Result<Value, NugetError> {
        Ok(self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

pub async fn lookup_artifact(
    provider: &dyn NugetProvider,
    package: &str,
    version: &str,
) -> Result<Artifact, NugetError> {
    let package = normalize_nuget_name(package);
    let version = normalize_nuget_version(version)
        .map_err(|err| NugetError::InvalidMetadata(err.to_string()))?;
    let index = provider.fetch_service_index().await?;
    let registration = index
        .get("resources")
        .and_then(Value::as_array)
        .and_then(|resources| {
            resources.iter().find_map(|resource| {
                resource
                    .get("@type")
                    .and_then(Value::as_str)
                    .filter(|kind| kind.starts_with("RegistrationsBaseUrl/"))
                    .and_then(|_| resource.get("@id"))
                    .and_then(Value::as_str)
            })
        })
        .ok_or_else(|| {
            NugetError::InvalidMetadata("service index has no registrations resource".into())
        })?;
    let root = provider
        .fetch_json(&format!(
            "{}/{}/index.json",
            registration.trim_end_matches('/'),
            package
        ))
        .await?;
    let leaf = find_leaf(provider, &root, &version).await?;
    let catalog = leaf.get("catalogEntry").unwrap_or(&leaf);
    let published_at = catalog
        .get("published")
        .and_then(Value::as_str)
        .and_then(parse_published);
    let upstream_url = leaf
        .get("packageContent")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            catalog
                .get("packageContent")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    Ok(Artifact {
        ecosystem: Ecosystem::Nuget,
        name: package,
        version,
        filename: None,
        upstream_url,
        published_at,
        hashes: Default::default(),
    })
}

async fn find_leaf(
    provider: &dyn NugetProvider,
    root: &Value,
    version: &str,
) -> Result<Value, NugetError> {
    let items = root
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| NugetError::InvalidMetadata("registration items must be an array".into()))?;
    for item in items {
        let page = if item.get("items").is_some() {
            item.clone()
        } else if let Some(id) = item.get("@id").and_then(Value::as_str) {
            provider.fetch_json(id).await?
        } else {
            continue;
        };
        if let Some(leaves) = page.get("items").and_then(Value::as_array) {
            if let Some(leaf) = leaves.iter().find(|leaf| {
                leaf.get("catalogEntry")
                    .and_then(|entry| entry.get("version"))
                    .and_then(Value::as_str)
                    .and_then(|candidate| normalize_nuget_version(candidate).ok())
                    .as_deref()
                    == Some(version)
            }) {
                return Ok(leaf.clone());
            }
        }
    }
    Err(NugetError::VersionNotFound(version.to_string()))
}

fn parse_published(value: &str) -> Option<DateTime<Utc>> {
    let timestamp = DateTime::parse_from_rfc3339(value)
        .ok()?
        .with_timezone(&Utc);
    (timestamp.year() > 1900).then_some(timestamp)
}

#[derive(Debug, Error)]
pub enum NugetError {
    #[error("NuGet upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("invalid NuGet metadata: {0}")]
    InvalidMetadata(String),
    #[error("NuGet version not found: {0}")]
    VersionNotFound(String),
}

use chrono::Datelike;
