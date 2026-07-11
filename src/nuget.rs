use crate::artifact::{Artifact, Ecosystem, normalize_nuget_name, normalize_nuget_version};
use crate::artifacts::{ArtifactDeliveryClient, ArtifactDeliveryError};
use crate::config::Config;
use crate::http_body::{self, HttpBodyError};
use crate::malicious::MaliciousChecker;
use crate::policy::PolicyEngine;
use crate::response::RegistryResponse;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::stream::{FuturesUnordered, StreamExt};
use serde_json::Value;
use std::time::Duration;
use thiserror::Error;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REGISTRATION_PAGES: usize = 64;
const MAX_NUGET_JSON_BYTES: usize = 32 * 1024 * 1024;
const REGISTRATION_PAGE_CONCURRENCY: usize = 8;

#[derive(Debug, Clone)]
pub struct NugetClient {
    service_index_url: String,
    client: ArtifactDeliveryClient,
    metadata_timeout: Duration,
}

impl NugetClient {
    pub fn for_config(config: &Config) -> Self {
        Self {
            service_index_url: config.upstreams.nuget.service_index_url.clone(),
            client: ArtifactDeliveryClient::for_config(config),
            metadata_timeout: REQUEST_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_dns_overrides(
        config: &Config,
        dns_overrides: std::collections::HashMap<String, Vec<std::net::SocketAddr>>,
    ) -> Self {
        Self {
            service_index_url: config.upstreams.nuget.service_index_url.clone(),
            client: ArtifactDeliveryClient::with_dns_overrides(config, dns_overrides),
            metadata_timeout: REQUEST_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(config: &Config, metadata_timeout: Duration) -> Self {
        Self {
            service_index_url: config.upstreams.nuget.service_index_url.clone(),
            client: ArtifactDeliveryClient::for_config(config),
            metadata_timeout,
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
        let response = self
            .client
            .fetch(Ecosystem::Nuget, url, self.metadata_timeout)
            .await?;
        if !response.status().is_success() {
            return Err(NugetError::InvalidMetadata(format!(
                "NuGet metadata returned HTTP status {}",
                response.status().as_u16()
            )));
        }
        Ok(http_body::collect_json(response, MAX_NUGET_JSON_BYTES, "NuGet V3 metadata").await?)
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
    let mut root = root;
    hydrate_registration_pages(provider, &mut root).await?;
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
    _provider: &dyn NugetProvider,
    root: &Value,
    version: &str,
) -> Result<Value, NugetError> {
    let items = root
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| NugetError::InvalidMetadata("registration items must be an array".into()))?;
    for item in items {
        let page = item;
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
    #[error("NuGet metadata destination failed egress validation: {0}")]
    Egress(#[from] ArtifactDeliveryError),
    #[error("NuGet upstream body failed validation: {0}")]
    Body(#[from] HttpBodyError),
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
    if let Some(index) = suffix
        .strip_prefix("page/")
        .and_then(|value| value.strip_suffix(".json"))
        .and_then(|value| value.parse::<usize>().ok())
    {
        let root = registration_response(config, provider, checker, package, now).await?;
        let root: Value = serde_json::from_slice(&root.body)?;
        let page = root
            .get("items")
            .and_then(Value::as_array)
            .and_then(|pages| pages.get(index))
            .cloned()
            .ok_or_else(|| NugetError::VersionNotFound(format!("page {index}")))?;
        return Ok(RegistryResponse::json(200, &page)?);
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
    if root
        .get("items")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        return Err(NugetError::VersionNotFound(suffix.to_string()));
    }
    let result = root["items"][0]["items"].clone();
    if suffix.ends_with(".json")
        && !suffix.contains("page/")
        && result.as_array().is_some_and(|items| items.len() == 1)
    {
        return Ok(RegistryResponse::json(200, &result[0])?);
    }
    if root["items"][0].is_null() {
        return Err(NugetError::VersionNotFound(suffix.to_string()));
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
    if pages.len() > MAX_REGISTRATION_PAGES {
        return Err(NugetError::InvalidMetadata(format!(
            "registration page count exceeds {MAX_REGISTRATION_PAGES}"
        )));
    }
    let mut requests = Vec::new();
    for (index, page) in pages.iter().enumerate() {
        if page.get("items").is_none() {
            let id = page
                .get("@id")
                .and_then(Value::as_str)
                .ok_or_else(|| NugetError::InvalidMetadata("registration page has no id".into()))?;
            requests.push((index, id.to_string()));
        }
    }
    let mut pending = FuturesUnordered::new();
    let mut next = 0;
    let mut results = Vec::new();
    while next < requests.len() || !pending.is_empty() {
        while next < requests.len() && pending.len() < REGISTRATION_PAGE_CONCURRENCY {
            let (index, id) = &requests[next];
            pending.push(async move { (*index, provider.fetch_json(id).await) });
            next += 1;
        }
        let (index, page) = pending.next().await.expect("pending nonempty");
        results.push((index, page?));
    }
    results.sort_by_key(|(index, _)| *index);
    for (index, hydrated) in results {
        let leaves = hydrated
            .get("items")
            .cloned()
            .ok_or_else(|| NugetError::InvalidMetadata("registration page has no items".into()))?;
        pages[index]
            .as_object_mut()
            .ok_or_else(|| {
                NugetError::InvalidMetadata("registration page is not an object".into())
            })?
            .insert("items".into(), leaves);
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
            if leaf.get("catalogEntry").is_some_and(Value::is_string) {
                return Err(NugetError::InvalidMetadata(
                    "string catalogEntry is unsupported".into(),
                ));
            }
            let catalog = leaf.get("catalogEntry").unwrap_or(leaf);
            let version = catalog
                .get("version")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    NugetError::InvalidMetadata("registration leaf has no version".into())
                })?;
            let version = normalize_nuget_version(version)
                .map_err(|err| NugetError::InvalidMetadata(err.to_string()))?;
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
        .await;
    let results = match checked {
        Ok(checked) if checked.len() == selected.len() => selected
            .iter()
            .zip(checked)
            .map(|((page, leaf, _), hits)| ((*page, *leaf), Ok(hits)))
            .collect::<std::collections::BTreeMap<_, _>>(),
        Ok(_) => selected
            .iter()
            .map(|(page, leaf, _)| {
                (
                    (*page, *leaf),
                    Err("OSV batch result cardinality mismatch".to_string()),
                )
            })
            .collect(),
        Err(error) => selected
            .iter()
            .map(|(page, leaf, _)| ((*page, *leaf), Err(error.to_string())))
            .collect(),
    };
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
            let result = results.get(&(page_index, leaf_index)).cloned();
            if policy
                .evaluate_with_malicious_result(artifact, now, result)
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
    if let Some(object) = document.as_object_mut() {
        object.insert(
            "@id".into(),
            Value::String(format!(
                "{base}/nuget/v3/registration-semver2/{package}/index.json"
            )),
        );
    }
    if let Some(items) = document.get_mut("items").and_then(Value::as_array_mut) {
        for (page_index, page) in items.iter_mut().enumerate() {
            if let Some(object) = page.as_object_mut() {
                object.insert(
                    "@id".into(),
                    Value::String(format!(
                        "{base}/nuget/v3/registration-semver2/{package}/page/{page_index}.json"
                    )),
                );
            }
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
                        object.insert(
                            "registration".into(),
                            Value::String(format!(
                                "{base}/nuget/v3/registration-semver2/{package}/index.json"
                            )),
                        );
                        if let Some(catalog) = object
                            .get_mut("catalogEntry")
                            .and_then(Value::as_object_mut)
                        {
                            catalog.insert(
                                "@id".into(),
                                Value::String(format!(
                                    "{base}/nuget/v3/registration-semver2/{package}/{version}.json"
                                )),
                            );
                        }
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
    use crate::config::{Config, OsvErrorBehavior};
    use crate::malicious::{MaliciousChecker, MaliciousError, MaliciousHit};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    struct Static {
        documents: HashMap<String, Value>,
    }
    struct Clean;
    struct Failing;
    #[async_trait]
    impl MaliciousChecker for Clean {
        async fn check(&self, _: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            Ok(Vec::new())
        }
    }
    #[async_trait]
    impl MaliciousChecker for Failing {
        async fn check(&self, _: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            Err(MaliciousError::Sync("fixture failure".to_string()))
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
            documents: HashMap::from([
                (
                    "https://upstream/registration/demo/index.json".into(),
                    json!({"items":[{"count":2,"items":[
                        {"catalogEntry":{"version":"1.0.0","published":"2026-01-01T00:00:00Z"},"packageContent":"https://upstream/demo.1.0.0.nupkg"},
                        {"catalogEntry":{"version":"2.0.0","published":"2026-07-11T00:00:00Z"},"packageContent":"https://upstream/demo.2.0.0.nupkg"}
                    ]}]}),
                ),
                (
                    "https://upstream/registration/demo/1.0.0.json".into(),
                    json!({"catalogEntry":{"version":"1.0.0","published":"2026-01-01T00:00:00Z","@id":"https://upstream/catalog"},"packageContent":"https://upstream/demo.1.0.0.nupkg","@id":"https://upstream/leaf"}),
                ),
            ]),
        }
    }
    #[tokio::test]
    async fn filters_registration_and_flat_container_versions() {
        let mut config = Config::default();
        config.policy.minimum_age = Duration::from_secs(24 * 60 * 60);
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
        let response =
            flat_container_index_response(&config, &provider(), &Clean, "Demo", Utc::now())
                .await
                .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&response.body).unwrap()["versions"],
            json!(["1.0.0"])
        );
    }
    #[tokio::test]
    async fn nuget_osv_batch_errors_follow_on_error_policy() {
        let mut document = provider()
            .documents
            .get("https://upstream/registration/demo/index.json")
            .unwrap()
            .clone();
        let mut config = Config::default();
        config.policy.minimum_age = Duration::ZERO;
        config.policy.osv.on_error = OsvErrorBehavior::Allow;
        filter_registration(&config, &Failing, "demo", &mut document, Utc::now())
            .await
            .unwrap();
        assert_eq!(document["items"][0]["items"].as_array().unwrap().len(), 2);

        let mut document = provider()
            .documents
            .get("https://upstream/registration/demo/index.json")
            .unwrap()
            .clone();
        config.policy.osv.on_error = OsvErrorBehavior::Block;
        filter_registration(&config, &Failing, "demo", &mut document, Utc::now())
            .await
            .unwrap();
        assert!(document["items"].as_array().unwrap().is_empty());
    }
    #[tokio::test]
    async fn registration_response_owns_all_emitted_urls() {
        let mut config = Config::default();
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
        let response = registration_response(&config, &provider(), &Clean, "demo", Utc::now())
            .await
            .unwrap();
        let body = String::from_utf8(response.body).unwrap();
        assert!(!body.contains("https://upstream"));
        assert!(body.contains("/nuget/v3/registration-semver2/demo/page/0.json"));
        assert!(body.contains("/nuget/v3/flatcontainer/demo/1.0.0/demo.1.0.0.nupkg"));
    }
    #[tokio::test]
    async fn hydration_fails_closed_over_page_cap() {
        let mut document = json!({"items": (0..=MAX_REGISTRATION_PAGES).map(|index| json!({"@id":format!("https://upstream/page/{index}.json")})).collect::<Vec<_>>()});
        let err = hydrate_registration_pages(&provider(), &mut document)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("page count exceeds"));
    }
    #[tokio::test]
    async fn rewritten_page_route_returns_page_shape() {
        let mut config = Config::default();
        config.policy.osv.block_malicious = false;
        let response = registration_resource_response(
            &config,
            &provider(),
            &Clean,
            "demo",
            "page/0.json",
            Utc::now(),
        )
        .await
        .unwrap();
        let page: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(page.get("items").and_then(Value::as_array).is_some());
        assert!(page["@id"].as_str().unwrap().ends_with("/page/0.json"));
        assert!(!page.to_string().contains("https://upstream"));
    }
    #[tokio::test]
    async fn rewritten_leaf_route_returns_owned_leaf() {
        let mut config = Config::default();
        config.policy.osv.block_malicious = false;
        let response = registration_resource_response(
            &config,
            &provider(),
            &Clean,
            "demo",
            "1.0.0.json",
            Utc::now(),
        )
        .await
        .unwrap();
        let leaf: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(leaf.get("catalogEntry").is_some());
        assert!(leaf["@id"].as_str().unwrap().ends_with("/demo/1.0.0.json"));
        assert!(
            leaf["catalogEntry"]["@id"]
                .as_str()
                .unwrap()
                .ends_with("/demo/1.0.0.json")
        );
        assert!(
            leaf["packageContent"]
                .as_str()
                .unwrap()
                .contains("/flatcontainer/demo/1.0.0/")
        );
        assert!(
            leaf["registration"]
                .as_str()
                .unwrap()
                .ends_with("/demo/index.json")
        );
        assert!(!leaf.to_string().contains("https://upstream"));
    }
    #[tokio::test]
    async fn blocked_direct_leaf_is_not_found() {
        let mut config = Config::default();
        config.policy.osv.block_malicious = false;
        config.blocklist.push(crate::config::BlocklistEntry {
            ecosystem: Ecosystem::Nuget,
            name: "demo".into(),
            versions: vec!["1.0.0".into()],
            reason: "test".into(),
        });
        let error = registration_resource_response(
            &config,
            &provider(),
            &Clean,
            "demo",
            "1.0.0.json",
            Utc::now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, NugetError::VersionNotFound(_)));
    }
    struct DelayedPages {
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl NugetProvider for DelayedPages {
        async fn fetch_service_index(&self) -> Result<Value, NugetError> {
            Ok(json!({}))
        }
        async fn fetch_json(&self, url: &str) -> Result<Value, NugetError> {
            let active = self.active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            self.peak.fetch_max(active, AtomicOrdering::SeqCst);
            let index = url
                .rsplit('/')
                .next()
                .unwrap()
                .trim_end_matches(".json")
                .parse::<u64>()
                .unwrap();
            tokio::time::sleep(Duration::from_millis(
                (REGISTRATION_PAGE_CONCURRENCY as u64 + 2 - index) * 2,
            ))
            .await;
            self.active.fetch_sub(1, AtomicOrdering::SeqCst);
            Ok(
                json!({"items":[{"catalogEntry":{"version":format!("1.0.{index}"),"published":"2020-01-01T00:00:00Z"}}]}),
            )
        }
    }
    #[tokio::test]
    async fn hydration_is_bounded_concurrent_and_reassembles_order() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let provider = DelayedPages {
            active: Arc::clone(&active),
            peak: Arc::clone(&peak),
        };
        let count = REGISTRATION_PAGE_CONCURRENCY + 2;
        let mut document = json!({"items": (0..count).map(|index| json!({"@id":format!("https://upstream/{index}.json")})).collect::<Vec<_>>()});
        hydrate_registration_pages(&provider, &mut document)
            .await
            .unwrap();
        assert!(peak.load(AtomicOrdering::SeqCst) > 1);
        assert!(peak.load(AtomicOrdering::SeqCst) <= REGISTRATION_PAGE_CONCURRENCY);
        assert_eq!(active.load(AtomicOrdering::SeqCst), 0);
        for index in 0..count {
            assert_eq!(
                document["items"][index]["items"][0]["catalogEntry"]["version"],
                json!(format!("1.0.{index}"))
            );
        }
    }

    #[tokio::test]
    async fn service_index_cannot_select_private_registration_origin() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/registration", target.local_addr().unwrap());
        let (upstream, origin) = bind_fixture().await;
        let served = serve_fixture(
            upstream,
            vec![json_response(&json!({"resources":[{
                "@type":"RegistrationsBaseUrl/3.6.0", "@id":target_url
            }]}))],
        );
        let mut config = Config::default();
        config.upstreams.nuget.service_index_url = format!("{origin}/index.json");

        let error = lookup_artifact(&NugetClient::for_config(&config), "demo", "1.0.0")
            .await
            .unwrap_err();

        assert!(matches!(error, NugetError::Egress(_)));
        served.await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn service_index_private_dns_answer_is_rejected_before_contact() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let registration = format!(
            "https://metadata.test:{}/registration",
            target_address.port()
        );
        let (upstream, origin) = bind_fixture().await;
        let served = serve_fixture(
            upstream,
            vec![json_response(&json!({"resources":[{
                "@type":"RegistrationsBaseUrl/3.6.0", "@id":registration
            }]}))],
        );
        let mut config = Config::default();
        config.upstreams.nuget.service_index_url = format!("{origin}/index.json");
        let client = NugetClient::with_dns_overrides(
            &config,
            HashMap::from([("metadata.test".to_string(), vec![target_address])]),
        );

        let error = lookup_artifact(&client, "demo", "1.0.0").await.unwrap_err();

        assert!(matches!(error, NugetError::Egress(_)));
        served.await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn registration_page_cannot_select_private_origin() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let page_url = format!("http://{}/page.json", target.local_addr().unwrap());
        let (upstream, origin) = bind_fixture().await;
        let registration = format!("{origin}/registration");
        let served = serve_fixture(
            upstream,
            vec![
                json_response(&json!({"resources":[{
                    "@type":"RegistrationsBaseUrl/3.6.0", "@id":registration
                }]})),
                json_response(&json!({"items":[{"@id":page_url}]})),
            ],
        );
        let mut config = Config::default();
        config.upstreams.nuget.service_index_url = format!("{origin}/index.json");

        let error = lookup_artifact(&NugetClient::for_config(&config), "demo", "1.0.0")
            .await
            .unwrap_err();

        assert!(matches!(error, NugetError::Egress(_)));
        served.await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn registration_redirect_to_private_origin_is_not_followed() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/secret", target.local_addr().unwrap());
        let (upstream, origin) = bind_fixture().await;
        let registration = format!("{origin}/registration");
        let served = serve_fixture(
            upstream,
            vec![
                json_response(&json!({"resources":[{
                    "@type":"RegistrationsBaseUrl/3.6.0", "@id":registration
                }]})),
                format!(
                    "HTTP/1.1 302 Found\r\nlocation: {target_url}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                ),
            ],
        );
        let mut config = Config::default();
        config.upstreams.nuget.service_index_url = format!("{origin}/index.json");

        let error = lookup_artifact(&NugetClient::for_config(&config), "demo", "1.0.0")
            .await
            .unwrap_err();

        assert!(matches!(error, NugetError::Egress(_)));
        served.await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn metadata_total_deadline_stops_a_progressing_body() {
        let (listener, origin) = bind_fixture().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _bytes_read = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 64\r\nconnection: close\r\n\r\n[",
                )
                .await
                .unwrap();
            for _ in 0..63 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                if stream.write_all(b" ").await.is_err() {
                    break;
                }
            }
        });
        let mut config = Config::default();
        config.upstreams.nuget.service_index_url = format!("{origin}/index.json");
        let client = NugetClient::with_timeout(&config, Duration::from_millis(35));

        let started = tokio::time::Instant::now();
        let error = client.fetch_service_index().await.unwrap_err();

        assert!(matches!(error, NugetError::Body(_)));
        assert!(started.elapsed() < Duration::from_millis(200));
        server.await.unwrap();
    }

    async fn bind_fixture() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        (listener, origin)
    }

    fn serve_fixture(listener: TcpListener, responses: Vec<String>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4096];
                let _bytes_read = stream.read(&mut request).await.unwrap();
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        })
    }

    fn json_response(value: &Value) -> String {
        let body = serde_json::to_vec(value).unwrap();
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8(body).unwrap()
        )
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
