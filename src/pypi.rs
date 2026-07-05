use crate::artifact::{normalize_pypi_name, Artifact, ArtifactHashes, Ecosystem};
use crate::config::Config;
use crate::malicious::MaliciousChecker;
use crate::policy::PolicyEngine;
use crate::response::RegistryResponse;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::header::ACCEPT;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use thiserror::Error;

const SIMPLE_JSON_CONTENT_TYPE: &str = "application/vnd.pypi.simple.v1+json";
const SIMPLE_HTML_CONTENT_TYPE: &str = "application/vnd.pypi.simple.v1+html";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct PypiSimpleClient {
    simple_url: String,
    client: Client,
}

impl PypiSimpleClient {
    pub fn new(simple_url: impl Into<String>) -> Self {
        Self {
            simple_url: simple_url.into().trim_end_matches('/').to_string(),
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("PyPI HTTP client should build with static timeout configuration"),
        }
    }
}

#[async_trait]
pub trait PypiSimpleProvider: Send + Sync {
    async fn fetch_simple_root(&self) -> Result<String, PypiError>;
    async fn fetch_project_json(&self, project: &str) -> Result<SimpleProject, PypiError>;
}

#[async_trait]
impl PypiSimpleProvider for PypiSimpleClient {
    async fn fetch_simple_root(&self) -> Result<String, PypiError> {
        Ok(self
            .client
            .get(&self.simple_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?)
    }

    async fn fetch_project_json(&self, project: &str) -> Result<SimpleProject, PypiError> {
        let project = normalize_pypi_name(project);
        Ok(self
            .client
            .get(format!("{}/{}/", self.simple_url, project))
            .header(
                ACCEPT,
                "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.latest+json",
            )
            .send()
            .await?
            .error_for_status()?
            .json::<SimpleProject>()
            .await?)
    }
}

pub fn package_artifact(
    name: impl AsRef<str>,
    version: impl Into<String>,
    published_at: Option<DateTime<Utc>>,
) -> Artifact {
    Artifact::package(Ecosystem::Pypi, name, version, published_at)
}

pub async fn simple_root_response(
    config: &Config,
    upstream: &dyn PypiSimpleProvider,
) -> Result<RegistryResponse, PypiError> {
    Ok(RegistryResponse::html(
        200,
        render_simple_root_html(config, &upstream.fetch_simple_root().await?),
    ))
}

pub async fn simple_project_response(
    config: &Config,
    upstream: &dyn PypiSimpleProvider,
    checker: &dyn MaliciousChecker,
    project: &str,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, PypiError> {
    simple_project_response_for_accept(config, upstream, checker, project, now, None).await
}

pub async fn simple_project_response_for_accept(
    config: &Config,
    upstream: &dyn PypiSimpleProvider,
    checker: &dyn MaliciousChecker,
    project: &str,
    now: DateTime<Utc>,
    accept: Option<&str>,
) -> Result<RegistryResponse, PypiError> {
    let project = normalize_pypi_name(project);
    let raw = upstream.fetch_project_json(&project).await?;
    let filtered = filter_simple_project(config, checker, &project, raw, now).await?;

    if wants_simple_json(accept) {
        let mut response = RegistryResponse::json(200, &serde_json::to_value(&filtered)?)?;
        response.set_content_type(SIMPLE_JSON_CONTENT_TYPE);
        Ok(response)
    } else {
        let mut response = RegistryResponse::html(200, render_simple_html(&filtered));
        response.set_content_type(SIMPLE_HTML_CONTENT_TYPE);
        Ok(response)
    }
}

pub async fn artifact_response(
    config: &Config,
    upstream: &dyn PypiSimpleProvider,
    checker: &dyn MaliciousChecker,
    project: &str,
    version: &str,
    filename: &str,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, PypiError> {
    let project = normalize_pypi_name(project);
    let raw = upstream.fetch_project_json(&project).await?;
    let file = raw
        .files
        .iter()
        .find(|file| file.filename == filename)
        .ok_or_else(|| {
            PypiError::FileNotFound(project.clone(), version.to_string(), filename.to_string())
        })?;
    let artifact = artifact_from_file(config, &project, file)?;
    if artifact.version != version {
        return Err(PypiError::FileNotFound(
            project,
            version.to_string(),
            filename.to_string(),
        ));
    }

    let decision = PolicyEngine::new(config)
        .evaluate(&artifact, now, checker)
        .await;
    if decision.allowed {
        Ok(RegistryResponse::redirect(
            artifact
                .upstream_url
                .ok_or_else(|| PypiError::MissingFileUrl(filename.to_string()))?,
        ))
    } else {
        let body = serde_json::to_value(decision)?;
        Ok(RegistryResponse::json(403, &body)?)
    }
}

pub fn error_response(error: &PypiError) -> RegistryResponse {
    let status = match error {
        PypiError::FileNotFound(_, _, _) | PypiError::InvalidFilename(_) => 404,
        PypiError::Upstream(_) => 502,
        PypiError::Json(_) | PypiError::InvalidSimpleJson(_) | PypiError::MissingFileUrl(_) => 500,
    };
    let body = json!({
        "allowed": false,
        "reason": "upstream_error",
        "message": error.to_string(),
    });
    RegistryResponse::json(status, &body).expect("static error response should serialize")
}

async fn filter_simple_project(
    config: &Config,
    checker: &dyn MaliciousChecker,
    project: &str,
    mut simple: SimpleProject,
    now: DateTime<Utc>,
) -> Result<SimpleProject, PypiError> {
    simple.name = normalize_pypi_name(&simple.name);
    if simple.name.is_empty() {
        simple.name = project.to_string();
    }

    let mut allowed_versions = BTreeSet::new();
    let mut allowed_files = Vec::new();
    let artifacts = simple
        .files
        .iter()
        .map(|file| artifact_from_file(config, project, file))
        .collect::<Result<Vec<_>, _>>()?;
    let policy = PolicyEngine::new(config);
    let artifacts_to_check = artifacts
        .iter()
        .enumerate()
        .filter(|(_, artifact)| !policy.bypasses_malicious(artifact))
        .map(|(index, artifact)| (index, artifact.clone()))
        .collect::<Vec<_>>();
    let checked_artifacts = artifacts_to_check
        .iter()
        .map(|(_, artifact)| artifact.clone())
        .collect::<Vec<_>>();
    let malicious_results = if checked_artifacts.is_empty() {
        Ok(Vec::new())
    } else {
        checker
            .check_many(&checked_artifacts)
            .await
            .map_err(|err| err.to_string())
    };

    for (index, mut file) in simple.files.into_iter().enumerate() {
        let artifact = &artifacts[index];
        let malicious_result = if let Some(batch_index) = artifacts_to_check
            .iter()
            .position(|(artifact_index, _)| *artifact_index == index)
        {
            match &malicious_results {
                Ok(results) => Some(Ok(results.get(batch_index).cloned().unwrap_or_default())),
                Err(err) => Some(Err(err.clone())),
            }
        } else {
            None
        };
        let decision = PolicyEngine::new(config).evaluate_with_malicious_result(
            artifact,
            now,
            malicious_result,
        );
        if decision.allowed {
            let version = artifact.version.clone();
            file.url = proxy_file_url(config, project, &version, &file.filename);
            allowed_versions.insert(version);
            allowed_files.push(file);
        }
    }

    simple.files = allowed_files;
    simple.versions = allowed_versions.into_iter().collect();
    Ok(simple)
}

fn artifact_from_file(
    config: &Config,
    project: &str,
    file: &SimpleFile,
) -> Result<Artifact, PypiError> {
    let version = infer_version_from_filename(project, &file.filename)
        .ok_or_else(|| PypiError::InvalidFilename(file.filename.clone()))?;
    let mut artifact = package_artifact(project, version, file.upload_time);
    artifact.filename = Some(file.filename.clone());
    artifact.upstream_url = Some(resolve_simple_href(config, project, &file.url));
    artifact.hashes = hashes_from_file(file);
    Ok(artifact)
}

fn hashes_from_file(file: &SimpleFile) -> ArtifactHashes {
    ArtifactHashes {
        sha256: file.hashes.get("sha256").cloned(),
        sha512: file.hashes.get("sha512").cloned(),
        integrity: None,
    }
}

fn wants_simple_json(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    accept
        .split(',')
        .map(|part| part.trim().to_ascii_lowercase())
        .any(|part| {
            let media_type = part.split(';').next().unwrap_or("").trim();
            media_type == SIMPLE_JSON_CONTENT_TYPE
                || media_type == "application/vnd.pypi.simple.latest+json"
                || media_type == "application/json"
        })
}

fn render_simple_html(simple: &SimpleProject) -> String {
    let mut html = String::from("<!DOCTYPE html>\n<html><body>\n");
    for file in &simple.files {
        html.push_str("<a href=\"");
        html.push_str(&escape_attr(&url_with_hash_fragment(file)));
        html.push('"');
        if let Some(requires_python) = &file.requires_python {
            html.push_str(" data-requires-python=\"");
            html.push_str(&escape_attr(requires_python));
            html.push('"');
        }
        if let Some(yanked) = &file.yanked {
            html.push_str(" data-yanked");
            if let Some(reason) = yanked.as_str() {
                html.push_str("=\"");
                html.push_str(&escape_attr(reason));
                html.push('"');
            }
        }
        if let Some(upload_time) = file.upload_time {
            html.push_str(" data-upload-time=\"");
            html.push_str(&upload_time.to_rfc3339());
            html.push('"');
        }
        html.push('>');
        html.push_str(&escape_text(&file.filename));
        html.push_str("</a>\n");
    }
    html.push_str("</body></html>\n");
    html
}

fn render_simple_root_html(config: &Config, upstream_html: &str) -> String {
    let mut projects = BTreeSet::new();
    for href in extract_href_values(upstream_html) {
        if let Some(project) = project_from_root_href(config, &href) {
            projects.insert(normalize_pypi_name(&project));
        }
    }

    let mut html = String::from("<!DOCTYPE html>\n<html><body>\n");
    for project in projects {
        if project.is_empty() {
            continue;
        }
        let href = format!(
            "{}/pypi/simple/{project}/",
            config.server.public_base_url.trim_end_matches('/')
        );
        html.push_str("<a href=\"");
        html.push_str(&escape_attr(&href));
        html.push_str("\">");
        html.push_str(&escape_text(&project));
        html.push_str("</a>\n");
    }
    html.push_str("</body></html>\n");
    html
}

fn extract_href_values(html: &str) -> Vec<String> {
    let mut hrefs = Vec::new();
    let mut rest = html;
    while let Some(index) = rest.find("href") {
        rest = &rest[index + "href".len()..];
        let trimmed = rest.trim_start();
        let Some(after_equals) = trimmed.strip_prefix('=') else {
            continue;
        };
        let after_equals = after_equals.trim_start();
        let Some(quote) = after_equals
            .chars()
            .next()
            .filter(|quote| *quote == '"' || *quote == '\'')
        else {
            continue;
        };
        let value_start = quote.len_utf8();
        let Some(value_end) = after_equals[value_start..].find(quote) else {
            break;
        };
        hrefs.push(after_equals[value_start..value_start + value_end].to_string());
        rest = &after_equals[value_start + value_end + quote.len_utf8()..];
    }
    hrefs
}

fn project_from_root_href(config: &Config, href: &str) -> Option<String> {
    let href = href.split('#').next().unwrap_or(href);
    let href = href.split('?').next().unwrap_or(href).trim();
    let simple_url = config.upstreams.pypi.simple_url.trim_end_matches('/');
    let rest = if let Some(rest) = href.strip_prefix('/') {
        rest.strip_prefix("simple/")?
    } else if href.starts_with("http://") || href.starts_with("https://") {
        if let Some(rest) = href.strip_prefix(&format!("{simple_url}/")) {
            rest
        } else {
            let origin = origin(simple_url)?;
            href.strip_prefix(&format!("{origin}/simple/"))?
        }
    } else {
        href
    };

    let project = rest.trim_matches('/');
    (!project.is_empty() && !project.contains('/')).then(|| project.to_string())
}

fn url_with_hash_fragment(file: &SimpleFile) -> String {
    if let Some(hash) = file.hashes.get("sha256") {
        if !file.url.contains('#') {
            return format!("{}#sha256={hash}", file.url);
        }
    }
    file.url.clone()
}

fn proxy_file_url(config: &Config, project: &str, version: &str, filename: &str) -> String {
    format!(
        "{}/pypi/packages/{}/{}/{}",
        config.server.public_base_url.trim_end_matches('/'),
        normalize_pypi_name(project),
        version,
        filename
    )
}

fn infer_version_from_filename(project: &str, filename: &str) -> Option<String> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let mut parts = stem.split('-');
        let distribution = parts.next()?;
        if normalize_pypi_name(distribution) != normalize_pypi_name(project) {
            return None;
        }
        return parts
            .next()
            .filter(|version| !version.is_empty())
            .map(ToOwned::to_owned);
    }

    let stem = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".tar.bz2"))
        .or_else(|| filename.strip_suffix(".zip"))
        .or_else(|| filename.strip_suffix(".tgz"))?;
    let pieces = stem.split('-').collect::<Vec<_>>();
    for index in 1..pieces.len() {
        if normalize_pypi_name(&pieces[..index].join("-")) == normalize_pypi_name(project) {
            return Some(pieces[index..].join("-"));
        }
    }
    stem.rsplit_once('-')
        .and_then(|(_, version)| (!version.is_empty()).then(|| version.to_string()))
}

fn resolve_simple_href(config: &Config, project: &str, href_without_fragment: &str) -> String {
    let href_without_fragment = href_without_fragment
        .split('#')
        .next()
        .unwrap_or(href_without_fragment);
    if href_without_fragment.starts_with("http://") || href_without_fragment.starts_with("https://")
    {
        return href_without_fragment.to_string();
    }
    if let Some(path) = href_without_fragment.strip_prefix("//") {
        return format!("https://{path}");
    }

    let simple_url = config.upstreams.pypi.simple_url.trim_end_matches('/');
    if href_without_fragment.starts_with('/') {
        if let Some(origin) = origin(simple_url) {
            return format!("{origin}{href_without_fragment}");
        }
    }

    normalize_url_path(&format!("{simple_url}/{project}/{href_without_fragment}"))
}

fn origin(url: &str) -> Option<&str> {
    let scheme_end = url.find("://")? + 3;
    let host_end = url[scheme_end..]
        .find('/')
        .map(|index| scheme_end + index)
        .unwrap_or(url.len());
    Some(&url[..host_end])
}

fn normalize_url_path(url: &str) -> String {
    let Some(scheme_end) = url.find("://").map(|index| index + 3) else {
        return url.to_string();
    };
    let Some(path_start) = url[scheme_end..].find('/').map(|index| scheme_end + index) else {
        return url.to_string();
    };
    let origin = &url[..path_start];
    let mut segments = Vec::new();
    for segment in url[path_start + 1..].split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            value => segments.push(value),
        }
    }
    format!("{origin}/{}", segments.join("/"))
}

fn escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimpleProject {
    #[serde(default)]
    pub meta: BTreeMap<String, Value>,
    pub name: String,
    #[serde(default)]
    pub files: Vec<SimpleFile>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimpleFile {
    pub filename: String,
    pub url: String,
    #[serde(default)]
    pub hashes: BTreeMap<String, String>,
    #[serde(
        default,
        rename = "requires-python",
        skip_serializing_if = "Option::is_none"
    )]
    pub requires_python: Option<String>,
    #[serde(
        default,
        rename = "dist-info-metadata",
        skip_serializing_if = "Option::is_none"
    )]
    pub dist_info_metadata: Option<Value>,
    #[serde(default, rename = "gpg-sig", skip_serializing_if = "Option::is_none")]
    pub gpg_sig: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yanked: Option<Value>,
    #[serde(
        default,
        rename = "upload-time",
        skip_serializing_if = "Option::is_none"
    )]
    pub upload_time: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Error)]
pub enum PypiError {
    #[error("PyPI upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("PyPI JSON handling failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid PyPI Simple JSON: {0}")]
    InvalidSimpleJson(String),
    #[error("invalid PyPI filename: {0}")]
    InvalidFilename(String),
    #[error("PyPI file URL missing for {0}")]
    MissingFileUrl(String),
    #[error("PyPI file not found for {0}@{1}: {2}")]
    FileNotFound(String, String, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AllowlistEntry, BlocklistEntry, MissingPublishTime};
    use crate::malicious::{MaliciousError, MaliciousHit};
    use crate::policy::{Decision, DecisionReason};
    use async_trait::async_trait;
    use chrono::Duration as ChronoDuration;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    struct StaticSimple {
        root: String,
        projects: HashMap<String, SimpleProject>,
    }

    impl StaticSimple {
        fn new(project: &str, simple: SimpleProject) -> Self {
            Self {
                root: "<html><body><a href=\"requests/\">requests</a></body></html>".to_string(),
                projects: HashMap::from([(normalize_pypi_name(project), simple)]),
            }
        }
    }

    #[async_trait]
    impl PypiSimpleProvider for StaticSimple {
        async fn fetch_simple_root(&self) -> Result<String, PypiError> {
            Ok(self.root.clone())
        }

        async fn fetch_project_json(&self, project: &str) -> Result<SimpleProject, PypiError> {
            self.projects
                .get(&normalize_pypi_name(project))
                .cloned()
                .ok_or_else(|| PypiError::InvalidSimpleJson(format!("missing {project}")))
        }
    }

    struct CleanChecker {
        calls: AtomicU32,
        batch_calls: AtomicU32,
        batch_artifacts: Mutex<Vec<String>>,
    }

    impl CleanChecker {
        fn new() -> Self {
            Self {
                calls: AtomicU32::new(0),
                batch_calls: AtomicU32::new(0),
                batch_artifacts: Mutex::new(Vec::new()),
            }
        }

        fn batch_identities(&self) -> Vec<String> {
            self.batch_artifacts.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MaliciousChecker for CleanChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }

        async fn check_many(
            &self,
            artifacts: &[Artifact],
        ) -> Result<Vec<Vec<MaliciousHit>>, MaliciousError> {
            self.batch_calls.fetch_add(1, Ordering::SeqCst);
            self.batch_artifacts
                .lock()
                .unwrap()
                .extend(artifacts.iter().map(Artifact::identity));
            Ok(vec![Vec::new(); artifacts.len()])
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn old_time() -> DateTime<Utc> {
        now() - ChronoDuration::hours(100)
    }

    fn new_time() -> DateTime<Utc> {
        now() - ChronoDuration::hours(12)
    }

    fn file(filename: &str, url: &str, upload_time: Option<DateTime<Utc>>) -> SimpleFile {
        SimpleFile {
            filename: filename.to_string(),
            url: url.to_string(),
            hashes: BTreeMap::from([("sha256".to_string(), format!("hash-{filename}"))]),
            requires_python: Some(">=3.9".to_string()),
            dist_info_metadata: None,
            gpg_sig: None,
            yanked: None,
            upload_time,
            extra: BTreeMap::new(),
        }
    }

    fn simple_fixture() -> SimpleProject {
        SimpleProject {
            meta: BTreeMap::from([("api-version".to_string(), json!("1.1"))]),
            name: "demo".to_string(),
            versions: vec![
                "1.0.0".to_string(),
                "1.0.1".to_string(),
                "2.0.0".to_string(),
            ],
            files: vec![
                file(
                    "demo-1.0.0.tar.gz",
                    "https://files.example/packages/demo-1.0.0.tar.gz",
                    Some(old_time()),
                ),
                file(
                    "demo-1.0.1.tar.gz",
                    "https://files.example/packages/demo-1.0.1.tar.gz",
                    Some(old_time()),
                ),
                file(
                    "demo-2.0.0-py3-none-any.whl",
                    "../../packages/demo-2.0.0-py3-none-any.whl",
                    Some(new_time()),
                ),
            ],
        }
    }

    #[tokio::test]
    async fn pypi_simple_json_filters_blocked_and_too_young_files_and_recomputes_versions() {
        let mut config = Config::default();
        config.server.public_base_url = "https://proxy.example/".to_string();
        config.upstreams.pypi.simple_url = "https://pypi.example/simple".to_string();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Pypi,
            name: "Demo".to_string(),
            versions: vec!["1.0.1".to_string()],
            reason: "known bad".to_string(),
        });
        let upstream = StaticSimple::new("Demo", simple_fixture());
        let checker = CleanChecker::new();

        let response = simple_project_response_for_accept(
            &config,
            &upstream,
            &checker,
            "Demo",
            now(),
            Some(SIMPLE_JSON_CONTENT_TYPE),
        )
        .await
        .unwrap();
        let body: SimpleProject = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(name, _)| name == "content-type")
                .map(|(_, value)| value.as_str()),
            Some(SIMPLE_JSON_CONTENT_TYPE)
        );
        assert_eq!(body.versions, vec!["1.0.0"]);
        assert_eq!(body.files.len(), 1);
        assert_eq!(body.files[0].filename, "demo-1.0.0.tar.gz");
        assert_eq!(
            body.files[0].url,
            "https://proxy.example/pypi/packages/demo/1.0.0/demo-1.0.0.tar.gz"
        );
        assert_eq!(body.files[0].upload_time, Some(old_time()));
        assert_eq!(checker.batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(checker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn pypi_simple_json_skips_malicious_batch_for_bypass_allowlist_files() {
        let mut config = Config::default();
        config.server.public_base_url = "https://proxy.example".to_string();
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::Pypi,
            name: "Demo".to_string(),
            version: "2.0.0".to_string(),
            bypass_age_gate: false,
            bypass_malicious: true,
            reason: "known false positive".to_string(),
        });
        let simple = SimpleProject {
            meta: BTreeMap::from([("api-version".to_string(), json!("1.1"))]),
            name: "Demo".to_string(),
            versions: vec!["1.0.0".to_string(), "2.0.0".to_string()],
            files: vec![
                file(
                    "demo-1.0.0.tar.gz",
                    "https://files.example/packages/demo-1.0.0.tar.gz",
                    Some(old_time()),
                ),
                file(
                    "demo-2.0.0-py3-none-any.whl",
                    "https://files.example/packages/demo-2.0.0-py3-none-any.whl",
                    Some(new_time()),
                ),
            ],
        };
        let upstream = StaticSimple::new("Demo", simple);
        let checker = CleanChecker::new();

        let response = simple_project_response_for_accept(
            &config,
            &upstream,
            &checker,
            "Demo",
            now(),
            Some(SIMPLE_JSON_CONTENT_TYPE),
        )
        .await
        .unwrap();
        let body: SimpleProject = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(body.versions, vec!["1.0.0"]);
        assert_eq!(body.files.len(), 1);
        assert_eq!(body.files[0].filename, "demo-1.0.0.tar.gz");
        assert_eq!(checker.batch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(checker.calls.load(Ordering::SeqCst), 0);
        assert_eq!(checker.batch_identities(), vec!["pypi:demo@1.0.0"]);
    }

    #[tokio::test]
    async fn pypi_simple_html_is_rendered_from_filtered_json_model() {
        let mut config = Config::default();
        config.server.public_base_url = "https://proxy.example".to_string();
        config.upstreams.pypi.simple_url = "https://pypi.example/simple".to_string();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Pypi,
            name: "demo".to_string(),
            versions: vec!["1.0.1".to_string()],
            reason: "known bad".to_string(),
        });
        let upstream = StaticSimple::new("demo", simple_fixture());
        let checker = CleanChecker::new();

        let response = simple_project_response(&config, &upstream, &checker, "demo", now())
            .await
            .unwrap();
        let body = String::from_utf8(response.body).unwrap();

        assert_eq!(response.status, 200);
        assert!(body.contains(
            "https://proxy.example/pypi/packages/demo/1.0.0/demo-1.0.0.tar.gz#sha256=hash-demo-1.0.0.tar.gz"
        ));
        assert!(body.contains("data-upload-time=\"2026-07-01T08:00:00+00:00\""));
        assert!(!body.contains("demo-1.0.1.tar.gz"));
        assert!(!body.contains("demo-2.0.0-py3-none-any.whl"));
    }

    #[tokio::test]
    async fn pypi_missing_json_upload_time_blocks_by_default() {
        let config = Config::default();
        let mut simple = simple_fixture();
        simple.files = vec![file(
            "demo-1.0.0.tar.gz",
            "https://files.example/packages/demo-1.0.0.tar.gz",
            None,
        )];
        let upstream = StaticSimple::new("demo", simple);
        let checker = CleanChecker::new();

        let response = simple_project_response_for_accept(
            &config,
            &upstream,
            &checker,
            "demo",
            now(),
            Some(SIMPLE_JSON_CONTENT_TYPE),
        )
        .await
        .unwrap();
        let body: SimpleProject = serde_json::from_slice(&response.body).unwrap();

        assert!(body.files.is_empty());
        assert!(body.versions.is_empty());
    }

    #[tokio::test]
    async fn pypi_missing_json_upload_time_can_be_allowed_explicitly() {
        let mut config = Config::default();
        config.policy.missing_publish_time = MissingPublishTime::Allow;
        let mut simple = simple_fixture();
        simple.files = vec![file(
            "demo-1.0.0.tar.gz",
            "https://files.example/packages/demo-1.0.0.tar.gz",
            None,
        )];
        let upstream = StaticSimple::new("demo", simple);
        let checker = CleanChecker::new();

        let response = simple_project_response_for_accept(
            &config,
            &upstream,
            &checker,
            "demo",
            now(),
            Some(SIMPLE_JSON_CONTENT_TYPE),
        )
        .await
        .unwrap();
        let body: SimpleProject = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(body.files.len(), 1);
        assert_eq!(body.versions, vec!["1.0.0"]);
    }

    #[tokio::test]
    async fn pypi_artifact_allowed_file_redirects_to_upstream_and_rechecks_policy() {
        let mut config = Config::default();
        config.upstreams.pypi.simple_url = "https://pypi.example/simple".to_string();
        let upstream = StaticSimple::new("demo", simple_fixture());
        let checker = CleanChecker::new();

        let response = artifact_response(
            &config,
            &upstream,
            &checker,
            "demo",
            "1.0.0",
            "demo-1.0.0.tar.gz",
            now(),
        )
        .await
        .unwrap();

        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            vec![(
                "location".to_string(),
                "https://files.example/packages/demo-1.0.0.tar.gz".to_string()
            )]
        );
        assert_eq!(checker.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pypi_artifact_blocked_file_returns_structured_403() {
        let mut config = Config::default();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Pypi,
            name: "demo".to_string(),
            versions: vec!["1.0.0".to_string()],
            reason: "known bad".to_string(),
        });
        let upstream = StaticSimple::new("demo", simple_fixture());
        let checker = CleanChecker::new();

        let response = artifact_response(
            &config,
            &upstream,
            &checker,
            "Demo",
            "1.0.0",
            "demo-1.0.0.tar.gz",
            now(),
        )
        .await
        .unwrap();
        let body: Decision = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status, 403);
        assert!(!body.allowed);
        assert_eq!(body.reason, DecisionReason::ManuallyBlocked);
        assert_eq!(body.package, "pypi:demo@1.0.0");
    }

    #[tokio::test]
    async fn pypi_artifact_too_young_file_returns_structured_403() {
        let config = Config::default();
        let upstream = StaticSimple::new("demo", simple_fixture());
        let checker = CleanChecker::new();

        let response = artifact_response(
            &config,
            &upstream,
            &checker,
            "demo",
            "2.0.0",
            "demo-2.0.0-py3-none-any.whl",
            now(),
        )
        .await
        .unwrap();
        let body: Decision = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status, 403);
        assert_eq!(body.reason, DecisionReason::TooYoung);
        assert_eq!(body.package, "pypi:demo@2.0.0");
    }

    #[tokio::test]
    async fn pypi_simple_root_rewrites_links_to_proxy_routes() {
        let mut config = Config::default();
        config.server.public_base_url = "https://proxy.example".to_string();
        config.upstreams.pypi.simple_url = "https://pypi.org/simple".to_string();
        let mut upstream = StaticSimple::new("demo", simple_fixture());
        upstream.root = r#"
<!DOCTYPE html>
<html><body>
  <a href="/simple/demo/">demo</a>
  <a href="relative-demo/">relative-demo</a>
  <a href="https://pypi.org/simple/Needs&Escape/">Needs&Escape</a>
</body></html>
"#
        .to_string();

        let response = simple_root_response(&config, &upstream).await.unwrap();
        let body = String::from_utf8(response.body).unwrap();

        assert_eq!(response.status, 200);
        assert!(body.contains("href=\"https://proxy.example/pypi/simple/demo/\""));
        assert!(body.contains("href=\"https://proxy.example/pypi/simple/relative-demo/\""));
        assert!(body.contains("href=\"https://proxy.example/pypi/simple/needs&amp;escape/\""));
        assert!(body.contains(">needs&amp;escape</a>"));
        assert!(!body.contains("href=\"/simple/demo/\""));
        assert!(!body.contains("href=\"relative-demo/\""));
        assert!(!body.contains("pypi.org/simple"));
    }

    #[test]
    fn pypi_artifacts_normalize_names_and_infer_versions() {
        let artifact = package_artifact(
            "My_Package.Name",
            "1.2.3",
            Some(now() - ChronoDuration::hours(100)),
        );
        assert_eq!(artifact.ecosystem, Ecosystem::Pypi);
        assert_eq!(artifact.name, "my-package-name");
        assert_eq!(
            infer_version_from_filename("my-package-name", "my_package.name-1.2.3.tar.gz"),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            infer_version_from_filename("demo", "demo-2.0.0-py3-none-any.whl"),
            Some("2.0.0".to_string())
        );
    }

    #[test]
    fn pypi_relative_links_resolve_against_project_simple_url() {
        let mut config = Config::default();
        config.upstreams.pypi.simple_url = "https://pypi.example/simple".to_string();

        assert_eq!(
            resolve_simple_href(&config, "demo", "../../packages/demo-1.0.0.tar.gz"),
            "https://pypi.example/packages/demo-1.0.0.tar.gz"
        );
    }
}
