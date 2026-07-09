//! GOPROXY protocol adapter. Go escaping and version semantics stay here so
//! policy continues to operate on ecosystem-neutral artifacts.
use crate::artifact::{Artifact, Ecosystem};
use crate::artifacts::ArtifactDeliveryOptions;
use crate::config::Config;
use crate::malicious::MaliciousChecker;
use crate::policy::PolicyEngine;
use crate::response::RegistryResponse;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{
    FutureExt,
    stream::{FuturesUnordered, StreamExt},
};
use node_semver::Version;
use reqwest::Client;
use serde::Deserialize;
use std::cmp::Ordering;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const LIST_INFO_CONCURRENCY: usize = 16;
const LIST_INFO_LIMIT: usize = 256;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GoInfo {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Time")]
    pub time: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum GoError {
    #[error("invalid Go module path or version: {0}")]
    InvalidRoute(String),
    #[error("Go upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("Go upstream returned HTTP status {0}")]
    UpstreamStatus(u16),
    #[error("invalid Go upstream response: {0}")]
    InvalidResponse(String),
}

#[async_trait]
pub trait GoProxyProvider: Send + Sync {
    async fn list(&self, module: &str) -> Result<Vec<String>, GoError>;
    async fn info(&self, module: &str, version: &str) -> Result<GoInfo, GoError>;
    fn resource_url(&self, module: &str, version: &str, extension: &str)
    -> Result<String, GoError>;
}

#[derive(Debug, Clone)]
pub struct GoProxyClient {
    base_url: String,
    client: Client,
}

impl GoProxyClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("static Go client configuration"),
        }
    }
    fn url(&self, module: &str, suffix: &str) -> Result<String, GoError> {
        Ok(format!(
            "{}/{}/{}",
            self.base_url,
            escape_module_path(module)?,
            suffix
        ))
    }
}

#[async_trait]
impl GoProxyProvider for GoProxyClient {
    async fn list(&self, module: &str) -> Result<Vec<String>, GoError> {
        let response = self.client.get(self.url(module, "@v/list")?).send().await?;
        if !response.status().is_success() {
            return Err(GoError::UpstreamStatus(response.status().as_u16()));
        }
        let body = response.text().await?;
        Ok(body
            .lines()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .collect())
    }
    async fn info(&self, module: &str, version: &str) -> Result<GoInfo, GoError> {
        let response = self
            .client
            .get(self.resource_url(module, version, "info")?)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(GoError::UpstreamStatus(response.status().as_u16()));
        }
        response
            .json()
            .await
            .map_err(|err| GoError::InvalidResponse(err.to_string()))
    }
    fn resource_url(
        &self,
        module: &str,
        version: &str,
        extension: &str,
    ) -> Result<String, GoError> {
        validate_version(version)?;
        self.url(
            module,
            &format!("@v/{}.{}", escape_go_component(version)?, extension),
        )
    }
}

pub fn artifact(module: &str, info: &GoInfo) -> Artifact {
    Artifact::package(Ecosystem::Go, module, &info.version, Some(info.time))
}

/// Go proxy escaping replaces each ASCII uppercase character with `!` plus its
/// lowercase form. Percent encoding is intentionally left to HTTP clients.
pub fn escape_go_component(value: &str) -> Result<String, GoError> {
    if value.is_empty() || value.contains('/') || value.contains('!') || value.contains("..") {
        return Err(GoError::InvalidRoute(value.to_string()));
    }
    Ok(value
        .chars()
        .flat_map(|ch| {
            if ch.is_ascii_uppercase() {
                vec!['!', ch.to_ascii_lowercase()]
            } else {
                vec![ch]
            }
        })
        .collect())
}

pub fn escape_module_path(module: &str) -> Result<String, GoError> {
    if module.is_empty()
        || module.starts_with('/')
        || module.ends_with('/')
        || module
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.contains('!'))
    {
        return Err(GoError::InvalidRoute(module.to_string()));
    }
    module
        .split('/')
        .map(escape_go_component)
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join("/"))
}

pub fn unescape_go_component(value: &str) -> Result<String, GoError> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '!' {
            let next = chars
                .next()
                .filter(|ch| ch.is_ascii_lowercase())
                .ok_or_else(|| GoError::InvalidRoute(value.into()))?;
            out.push(next.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

fn unescape_module_path(value: &str) -> Result<String, GoError> {
    let module = value
        .split('/')
        .map(unescape_go_component)
        .collect::<Result<Vec<_>, _>>()?
        .join("/");
    escape_module_path(&module)?;
    Ok(module)
}

pub fn validate_version(version: &str) -> Result<(), GoError> {
    if !version.starts_with('v')
        || version.contains('/')
        || version.contains('!')
        || version.contains("..")
    {
        return Err(GoError::InvalidRoute(version.to_string()));
    }
    Ok(())
}

/// Comparison follows Go's canonical semver spelling, treating the permitted
/// `+incompatible` suffix as metadata. Go pseudo versions are ordinary semver
/// prereleases and therefore compare correctly with this parser.
pub fn compare_versions(left: &str, right: &str) -> Result<Ordering, GoError> {
    let left = left.strip_suffix("+incompatible").unwrap_or(left);
    let right = right.strip_suffix("+incompatible").unwrap_or(right);
    Version::parse(left)
        .map_err(|_| GoError::InvalidRoute(left.to_string()))?
        .partial_cmp(&Version::parse(right).map_err(|_| GoError::InvalidRoute(right.to_string()))?)
        .ok_or_else(|| GoError::InvalidRoute(format!("{left}, {right}")))
}

pub async fn route_response(
    config: &Config,
    upstream: &dyn GoProxyProvider,
    checker: &dyn MaliciousChecker,
    module: &str,
    route: GoRoute<'_>,
    now: DateTime<Utc>,
    delivery: Option<ArtifactDeliveryOptions<'_>>,
) -> Result<RegistryResponse, GoError> {
    match route {
        GoRoute::List => {
            let mut allowed = filtered_infos(config, upstream, checker, module, now)
                .await?
                .into_iter()
                .map(|info| info.version)
                .collect::<Vec<_>>();
            allowed.sort_by(|a, b| compare_versions(a, b).unwrap_or_else(|_| a.cmp(b)));
            allowed.dedup();
            Ok(RegistryResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/plain; charset=UTF-8".into())],
                body: if allowed.is_empty() {
                    Vec::new()
                } else {
                    format!("{}\n", allowed.join("\n")).into_bytes()
                },
            })
        }
        GoRoute::Latest => {
            let selected = filtered_infos(config, upstream, checker, module, now)
                .await?
                .into_iter()
                .max_by(|left, right| {
                    compare_versions(&left.version, &right.version)
                        .unwrap_or_else(|_| left.version.cmp(&right.version))
                });
            selected.map(|info| RegistryResponse::json(200, &serde_json::json!({"Version": info.version, "Time": info.time.to_rfc3339()})).map_err(|err| GoError::InvalidResponse(err.to_string()))).unwrap_or_else(|| Err(GoError::UpstreamStatus(404)))
        }
        GoRoute::Info(version) => {
            let info = upstream.info(module, version).await?;
            let decision = PolicyEngine::new(config)
                .evaluate(&artifact(module, &info), now, checker)
                .await;
            if !decision.allowed {
                return RegistryResponse::json(403, &serde_json::to_value(decision).unwrap())
                    .map_err(|err| GoError::InvalidResponse(err.to_string()));
            }
            RegistryResponse::json(
                200,
                &serde_json::json!({"Version": info.version, "Time": info.time.to_rfc3339()}),
            )
            .map_err(|err| GoError::InvalidResponse(err.to_string()))
        }
        GoRoute::Content { version, extension } => {
            let info = upstream.info(module, version).await?;
            let decision = PolicyEngine::new(config)
                .evaluate(&artifact(module, &info), now, checker)
                .await;
            if !decision.allowed {
                return RegistryResponse::json(403, &serde_json::to_value(decision).unwrap())
                    .map_err(|err| GoError::InvalidResponse(err.to_string()));
            }
            let delivery = delivery
                .ok_or_else(|| GoError::InvalidResponse("missing artifact delivery".into()))?;
            Ok(delivery
                .client
                .deliver(
                    config,
                    upstream.resource_url(module, version, extension)?,
                    delivery.request_headers,
                )
                .await
                .map_err(|err| GoError::InvalidResponse(err.to_string()))?
                .into_registry_response()
                .await)
        }
    }
}

async fn filtered_infos(
    config: &Config,
    upstream: &dyn GoProxyProvider,
    checker: &dyn MaliciousChecker,
    module: &str,
    now: DateTime<Utc>,
) -> Result<Vec<GoInfo>, GoError> {
    let versions = upstream.list(module).await?;
    let mut pending = FuturesUnordered::new();
    let mut versions = versions.into_iter().take(LIST_INFO_LIMIT);
    for _ in 0..LIST_INFO_CONCURRENCY {
        if let Some(version) = versions.next() {
            pending.push(async move { upstream.info(module, &version).await }.boxed());
        }
    }
    let mut infos = Vec::new();
    let mut failed = None;
    while let Some(result) = pending.next().await {
        match result {
            Ok(info) => infos.push(info),
            Err(error) => failed = Some(error),
        }
        if let Some(version) = versions.next() {
            pending.push(async move { upstream.info(module, &version).await }.boxed());
        }
    }
    if let Some(error) = failed {
        return Err(error);
    }
    let mut allowed = Vec::new();
    for info in infos {
        if PolicyEngine::new(config)
            .evaluate(&artifact(module, &info), now, checker)
            .await
            .allowed
        {
            allowed.push(info);
        }
    }
    Ok(allowed)
}

#[derive(Debug, Clone, Copy)]
pub enum GoRoute<'a> {
    List,
    Latest,
    Info(&'a str),
    Content {
        version: &'a str,
        extension: &'a str,
    },
}

pub fn parse_route(path: &str) -> Option<(String, GoRoute<'_>)> {
    let raw = path.strip_prefix("/go/")?.trim_start_matches('/');
    let (module, suffix) = raw.split_once("/@")?;
    let module = unescape_module_path(module).ok()?;
    match suffix {
        "v/list" => Some((module, GoRoute::List)),
        "latest" => Some((module, GoRoute::Latest)),
        _ => {
            let (version, ext) = suffix.strip_prefix("v/")?.rsplit_once('.')?;
            if validate_version(version).is_err() {
                return None;
            }
            match ext {
                "info" => Some((module, GoRoute::Info(version))),
                "mod" | "zip" => Some((
                    module,
                    GoRoute::Content {
                        version,
                        extension: ext,
                    },
                )),
                _ => None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escapes_uppercase_path_segments() {
        assert_eq!(
            escape_module_path("GitHub.com/Acme/Thing/v2").unwrap(),
            "!git!hub.com/!acme/!thing/v2"
        );
    }
    #[test]
    fn rejects_traversal() {
        assert!(escape_module_path("example.com/../bad").is_err());
    }
    #[test]
    fn go_versions_handle_pseudo_and_incompatible() {
        assert_eq!(
            compare_versions("v1.2.4-0.20200101000000-abcdefabcdef", "v1.2.3").unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("v2.0.0+incompatible", "v2.0.0").unwrap(),
            Ordering::Equal
        );
    }

    #[test]
    fn go_modules_parse_proxy_routes() {
        let (module, route) = parse_route("/go/!git!hub.com/!acme/!thing/@v/v2.0.0.mod").unwrap();
        assert_eq!(module, "GitHub.com/Acme/Thing");
        assert!(matches!(
            route,
            GoRoute::Content {
                extension: "mod",
                ..
            }
        ));
        assert!(parse_route("/go/example.com/../bad/@v/list").is_none());
    }
}
