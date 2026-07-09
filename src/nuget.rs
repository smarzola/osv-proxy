use crate::artifact::{Artifact, Ecosystem, normalize_nuget_name, normalize_nuget_version};
use crate::config::Config;
use crate::malicious::MaliciousChecker;
use crate::policy::PolicyEngine;
use crate::response::RegistryResponse;
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
        if let Some(leaves) = page.get("items").and_then(Value::as_array)
            && let Some(leaf) = leaves.iter().find(|leaf| {
                leaf.get("catalogEntry")
                    .and_then(|entry| entry.get("version"))
                    .and_then(Value::as_str)
                    .and_then(|candidate| normalize_nuget_version(candidate).ok())
                    .as_deref()
                    == Some(version)
            })
        {
            return Ok(leaf.clone());
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
    #[error("NuGet response serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid NuGet metadata: {0}")]
    InvalidMetadata(String),
    #[error("NuGet version not found: {0}")]
    VersionNotFound(String),
}

pub fn service_index_response(config: &Config) -> Result<RegistryResponse, NugetError> {
    let base = config.server.public_base_url.trim_end_matches('/');
    Ok(RegistryResponse::json(
        200,
        &serde_json::json!({"version":"3.0.0","resources":[
            {"@id":format!("{base}/nuget/v3/registration-semver2/"),"@type":"RegistrationsBaseUrl/3.6.0"},
            {"@id":format!("{base}/nuget/v3/flatcontainer/"),"@type":"PackageBaseAddress/3.0.0"}
        ]}),
    )?)
}

pub async fn registration_response(
    config: &Config,
    provider: &dyn NugetProvider,
    checker: &dyn MaliciousChecker,
    package: &str,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, NugetError> {
    let index = provider.fetch_service_index().await?;
    let base = registration_base(&index)?.trim_end_matches('/');
    let package = normalize_nuget_name(package);
    let mut document = provider
        .fetch_json(&format!("{base}/{package}/index.json"))
        .await?;
    hydrate_registration_pages(provider, &mut document).await?;
    filter_registration(config, checker, &package, &mut document, now).await?;
    rewrite_registration_urls(config, &package, &mut document);
    Ok(RegistryResponse::json(200, &document)?)
}

pub async fn registration_resource_response(
    config: &Config,
    provider: &dyn NugetProvider,
    checker: &dyn MaliciousChecker,
    package: &str,
    suffix: &str,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, NugetError> {
    if suffix == "index.json" {
        return registration_response(config, provider, checker, package, now).await;
    }
    let index = provider.fetch_service_index().await?;
    let base = registration_base(&index)?.trim_end_matches('/');
    let package = normalize_nuget_name(package);
    let raw = provider
        .fetch_json(&format!("{base}/{package}/{suffix}"))
        .await?;
    let mut root = if raw.get("catalogEntry").is_some() {
        serde_json::json!({"items":[{"items":[raw]}]})
    } else {
        serde_json::json!({"items":[raw]})
    };
    filter_registration(config, checker, &package, &mut root, now).await?;
    rewrite_registration_urls(config, &package, &mut root);
    let result = root["items"][0]["items"].clone();
    if suffix.ends_with(".json")
        && !suffix.contains("page/")
        && result.as_array().is_some_and(|items| items.len() == 1)
    {
        return Ok(RegistryResponse::json(200, &result[0])?);
    }
    Ok(RegistryResponse::json(200, &root["items"][0])?)
}

async fn hydrate_registration_pages(
    provider: &dyn NugetProvider,
    document: &mut Value,
) -> Result<(), NugetError> {
    let pages = document
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| NugetError::InvalidMetadata("registration items must be an array".into()))?;
    for page in pages {
        if page.get("items").is_none() {
            let id = page
                .get("@id")
                .and_then(Value::as_str)
                .ok_or_else(|| NugetError::InvalidMetadata("registration page has no id".into()))?
                .to_string();
            let hydrated = provider.fetch_json(&id).await?;
            let leaves = hydrated.get("items").cloned().ok_or_else(|| {
                NugetError::InvalidMetadata("registration page has no items".into())
            })?;
            page.as_object_mut()
                .ok_or_else(|| {
                    NugetError::InvalidMetadata("registration page is not an object".into())
                })?
                .insert("items".into(), leaves);
        }
    }
    Ok(())
}

pub async fn flat_container_index_response(
    config: &Config,
    provider: &dyn NugetProvider,
    checker: &dyn MaliciousChecker,
    package: &str,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, NugetError> {
    let index = provider.fetch_service_index().await?;
    let base = registration_base(&index)?.trim_end_matches('/');
    let package = normalize_nuget_name(package);
    let mut document = provider
        .fetch_json(&format!("{base}/{package}/index.json"))
        .await?;
    hydrate_registration_pages(provider, &mut document).await?;
    filter_registration(config, checker, &package, &mut document, now).await?;
    let versions = document
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|page| {
            page.get("items")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|leaf| {
            leaf.get("catalogEntry")
                .and_then(|entry| entry.get("version"))
                .and_then(Value::as_str)
        })
        .filter_map(|version| normalize_nuget_version(version).ok())
        .collect::<Vec<_>>();
    Ok(RegistryResponse::json(
        200,
        &serde_json::json!({"versions": versions}),
    )?)
}

fn registration_base(index: &Value) -> Result<&str, NugetError> {
    index
        .get("resources")
        .and_then(Value::as_array)
        .and_then(|resources| {
            resources.iter().find_map(|r| {
                r.get("@type")
                    .and_then(Value::as_str)
                    .filter(|t| t.starts_with("RegistrationsBaseUrl/"))
                    .and_then(|_| r.get("@id"))
                    .and_then(Value::as_str)
            })
        })
        .ok_or_else(|| {
            NugetError::InvalidMetadata("service index has no registrations resource".into())
        })
}

async fn filter_registration(
    config: &Config,
    checker: &dyn MaliciousChecker,
    package: &str,
    document: &mut Value,
    now: DateTime<Utc>,
) -> Result<(), NugetError> {
    let items = document
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| NugetError::InvalidMetadata("registration items must be an array".into()))?;
    let mut artifacts = Vec::new();
    for (page_index, page) in items.iter().enumerate() {
        for (leaf_index, leaf) in page
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| NugetError::InvalidMetadata("registration page has no items".into()))?
            .iter()
            .enumerate()
        {
            let catalog = leaf.get("catalogEntry").unwrap_or(leaf);
            let version = catalog
                .get("version")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    NugetError::InvalidMetadata("registration leaf has no version".into())
                })?;
            artifacts.push((
                page_index,
                leaf_index,
                Artifact::package(
                    Ecosystem::Nuget,
                    package,
                    version,
                    catalog
                        .get("published")
                        .and_then(Value::as_str)
                        .and_then(parse_published),
                ),
            ));
        }
    }
    let policy = PolicyEngine::new(config);
    let selected = artifacts
        .iter()
        .filter(|(_, _, artifact)| policy.should_check_osv(artifact))
        .cloned()
        .collect::<Vec<_>>();
    let checked = checker
        .check_many(
            &selected
                .iter()
                .map(|(_, _, artifact)| artifact.clone())
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(|err| NugetError::InvalidMetadata(format!("malicious batch failed: {err}")))?;
    if checked.len() != selected.len() {
        return Err(NugetError::InvalidMetadata(
            "malicious batch returned wrong result count".into(),
        ));
    }
    let results = selected
        .into_iter()
        .zip(checked)
        .map(|((page, leaf, _), hits)| ((page, leaf), hits))
        .collect::<std::collections::BTreeMap<_, _>>();
    for (page_index, page) in items.iter_mut().enumerate() {
        let leaves = page
            .get_mut("items")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| {
                NugetError::InvalidMetadata(
                    "paged registrations are unsupported without inline leaves".into(),
                )
            })?;
        let mut kept = Vec::new();
        for (leaf_index, leaf) in leaves.drain(..).enumerate() {
            let artifact = &artifacts
                .iter()
                .find(|(page, leaf, _)| *page == page_index && *leaf == leaf_index)
                .expect("collected leaf")
                .2;
            let result = results.get(&(page_index, leaf_index)).cloned().map(Ok);
            if policy
                .evaluate_with_malicious_result(artifact, now, result.map(|hits| hits))
                .allowed
            {
                kept.push(leaf);
            }
        }
        *leaves = kept;
        let kept_count = leaves.len();
        if let Some(page_count) = page.get_mut("count") {
            *page_count = Value::from(kept_count);
        }
    }
    items.retain(|page| {
        page.get("items")
            .and_then(Value::as_array)
            .is_some_and(|leaves| !leaves.is_empty())
    });
    Ok(())
}

fn rewrite_registration_urls(config: &Config, package: &str, document: &mut Value) {
    let base = config.server.public_base_url.trim_end_matches('/');
    if let Some(items) = document.get_mut("items").and_then(Value::as_array_mut) {
        for page in items {
            if let Some(leaves) = page.get_mut("items").and_then(Value::as_array_mut) {
                for leaf in leaves {
                    let version = leaf
                        .get("catalogEntry")
                        .and_then(|c| c.get("version"))
                        .and_then(Value::as_str)
                        .and_then(|v| normalize_nuget_version(v).ok());
                    if let Some(version) = version
                        && let Some(object) = leaf.as_object_mut()
                    {
                        object.insert(
                            "@id".into(),
                            Value::String(format!(
                                "{base}/nuget/v3/registration-semver2/{package}/{version}.json"
                            )),
                        );
                        object.insert("packageContent".into(),Value::String(format!("{base}/nuget/v3/flatcontainer/{package}/{version}/{package}.{version}.nupkg")));
                    }
                }
            }
        }
    }
}

use chrono::Datelike;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::malicious::{MaliciousChecker, MaliciousError, MaliciousHit};
    use serde_json::json;
    use std::collections::HashMap;

    struct Static {
        documents: HashMap<String, Value>,
    }
    struct Clean;
    #[async_trait]
    impl MaliciousChecker for Clean {
        async fn check(&self, _: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            Ok(Vec::new())
        }
    }
    #[async_trait]
    impl NugetProvider for Static {
        async fn fetch_service_index(&self) -> Result<Value, NugetError> {
            Ok(
                json!({"resources":[{"@type":"RegistrationsBaseUrl/3.6.0","@id":"https://upstream/registration"}]}),
            )
        }
        async fn fetch_json(&self, url: &str) -> Result<Value, NugetError> {
            self.documents
                .get(url)
                .cloned()
                .ok_or_else(|| NugetError::InvalidMetadata(url.into()))
        }
    }
    fn provider() -> Static {
        Static {
            documents: HashMap::from([(
                "https://upstream/registration/demo/index.json".into(),
                json!({"items":[{"count":2,"items":[
                    {"catalogEntry":{"version":"1.0.0","published":"2026-01-01T00:00:00Z"},"packageContent":"https://upstream/demo.1.0.0.nupkg"},
                    {"catalogEntry":{"version":"2.0.0","published":"2026-07-09T00:00:00Z"},"packageContent":"https://upstream/demo.2.0.0.nupkg"}
                ]}]}),
            )]),
        }
    }
    #[tokio::test]
    async fn filters_registration_and_flat_container_versions() {
        let mut config = Config::default();
        config.policy.minimum_age = Duration::from_secs(24 * 60 * 60);
        config.policy.osv.block_malicious = false;
        let response =
            flat_container_index_response(&config, &provider(), &Clean, "Demo", Utc::now())
                .await
                .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap()["versions"],
            json!(["1.0.0"])
        );
    }
    #[test]
    fn service_index_owns_only_restore_resources() {
        let response = service_index_response(&Config::default()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap()["resources"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
