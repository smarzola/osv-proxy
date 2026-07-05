use crate::artifact::{normalize_pypi_name, Artifact, ArtifactHashes, Ecosystem};
use crate::config::Config;
use crate::malicious::MaliciousChecker;
use crate::policy::PolicyEngine;
use crate::response::RegistryResponse;
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct PypiSimpleClient {
    simple_url: String,
    client: Client,
}

impl PypiSimpleClient {
    pub fn new(simple_url: impl Into<String>) -> Self {
        Self {
            simple_url: simple_url.into().trim_end_matches('/').to_string(),
            client: Client::new(),
        }
    }
}

pub trait PypiSimpleProvider {
    fn fetch_simple_root(&self) -> Result<String, PypiError>;
    fn fetch_project_simple(&self, project: &str) -> Result<String, PypiError>;
}

impl PypiSimpleProvider for PypiSimpleClient {
    fn fetch_simple_root(&self) -> Result<String, PypiError> {
        Ok(self
            .client
            .get(&self.simple_url)
            .send()?
            .error_for_status()?
            .text()?)
    }

    fn fetch_project_simple(&self, project: &str) -> Result<String, PypiError> {
        let project = normalize_pypi_name(project);
        Ok(self
            .client
            .get(format!("{}/{}/", self.simple_url, project))
            .send()?
            .error_for_status()?
            .text()?)
    }
}

pub fn package_artifact(
    name: impl AsRef<str>,
    version: impl Into<String>,
    published_at: Option<DateTime<Utc>>,
) -> Artifact {
    Artifact::package(Ecosystem::Pypi, name, version, published_at)
}

pub fn simple_root_response(
    upstream: &dyn PypiSimpleProvider,
) -> Result<RegistryResponse, PypiError> {
    Ok(RegistryResponse::html(200, upstream.fetch_simple_root()?))
}

pub fn simple_project_response(
    config: &Config,
    upstream: &dyn PypiSimpleProvider,
    checker: &dyn MaliciousChecker,
    project: &str,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, PypiError> {
    let project = normalize_pypi_name(project);
    let raw = upstream.fetch_project_simple(&project)?;
    let filtered = filter_simple_project_html(config, checker, &project, &raw, now)?;
    Ok(RegistryResponse::html(200, filtered))
}

pub fn artifact_response(
    config: &Config,
    upstream: &dyn PypiSimpleProvider,
    checker: &dyn MaliciousChecker,
    project: &str,
    version: &str,
    filename: &str,
    now: DateTime<Utc>,
) -> Result<RegistryResponse, PypiError> {
    let project = normalize_pypi_name(project);
    let raw = upstream.fetch_project_simple(&project)?;
    let link = find_file_link(config, &project, version, filename, &raw)?.ok_or_else(|| {
        PypiError::FileNotFound(project.clone(), version.to_string(), filename.to_string())
    })?;
    let artifact = artifact_from_link(config, &project, &link)?;
    let decision = PolicyEngine::new(config).evaluate(&artifact, now, checker);

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
        PypiError::Json(_) | PypiError::InvalidSimpleHtml(_) | PypiError::MissingFileUrl(_) => 500,
    };
    let body = json!({
        "allowed": false,
        "reason": "upstream_error",
        "message": error.to_string(),
    });
    RegistryResponse::json(status, &body).expect("static error response should serialize")
}

fn filter_simple_project_html(
    config: &Config,
    checker: &dyn MaliciousChecker,
    project: &str,
    html: &str,
    now: DateTime<Utc>,
) -> Result<String, PypiError> {
    rewrite_anchor_links(html, |link| {
        let artifact = artifact_from_link(config, project, link)?;
        let decision = PolicyEngine::new(config).evaluate(&artifact, now, checker);
        if decision.allowed {
            let fragment = split_fragment(&link.href).1.unwrap_or_default();
            Ok(Some(format!(
                "{}/pypi/packages/{}/{}/{}{}",
                config.server.public_base_url.trim_end_matches('/'),
                project,
                artifact.version,
                artifact
                    .filename
                    .as_deref()
                    .ok_or_else(|| PypiError::InvalidFilename(link.href.clone()))?,
                fragment
            )))
        } else {
            Ok(None)
        }
    })
}

fn find_file_link(
    config: &Config,
    project: &str,
    version: &str,
    filename: &str,
    html: &str,
) -> Result<Option<SimpleLink>, PypiError> {
    let mut found = None;
    rewrite_anchor_links(html, |link| {
        let artifact = artifact_from_link(config, project, link)?;
        if artifact.version == version && artifact.filename.as_deref() == Some(filename) {
            found = Some(link.clone());
        }
        Ok(Some(link.href.clone()))
    })?;
    Ok(found)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SimpleLink {
    href: String,
    upload_time: Option<DateTime<Utc>>,
}

fn rewrite_anchor_links<F>(html: &str, mut decide: F) -> Result<String, PypiError>
where
    F: FnMut(&SimpleLink) -> Result<Option<String>, PypiError>,
{
    let mut output = String::with_capacity(html.len());
    let mut cursor = 0;

    while let Some(relative_start) = html[cursor..].to_ascii_lowercase().find("<a") {
        let start = cursor + relative_start;
        output.push_str(&html[cursor..start]);
        let Some(open_end_relative) = html[start..].find('>') else {
            output.push_str(&html[start..]);
            return Ok(output);
        };
        let open_end = start + open_end_relative + 1;
        let close_end = html[open_end..]
            .to_ascii_lowercase()
            .find("</a>")
            .map(|close_start_relative| open_end + close_start_relative + "</a>".len())
            .unwrap_or(open_end);
        let anchor = &html[start..close_end];
        let opening = &html[start..open_end];

        if let Some(href) = attr_value(opening, "href") {
            let link = SimpleLink {
                href,
                upload_time: attr_value(opening, "data-upload-time")
                    .and_then(|raw| parse_pypi_time(&raw)),
            };
            if let Some(new_href) = decide(&link)? {
                output.push_str(&replace_href(anchor, &new_href));
            }
        } else {
            output.push_str(anchor);
        }
        cursor = close_end;
    }

    output.push_str(&html[cursor..]);
    Ok(output)
}

fn artifact_from_link(
    config: &Config,
    project: &str,
    link: &SimpleLink,
) -> Result<Artifact, PypiError> {
    let (href_without_fragment, fragment) = split_fragment(&link.href);
    let filename = filename_from_href(href_without_fragment)
        .ok_or_else(|| PypiError::InvalidFilename(link.href.clone()))?;
    let version = infer_version_from_filename(project, &filename)
        .ok_or_else(|| PypiError::InvalidFilename(filename.clone()))?;
    let mut artifact = package_artifact(project, version, link.upload_time);
    artifact.filename = Some(filename);
    artifact.upstream_url = Some(resolve_simple_href(config, project, href_without_fragment));
    artifact.hashes = hashes_from_fragment(fragment);
    Ok(artifact)
}

fn infer_version_from_filename(project: &str, filename: &str) -> Option<String> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let mut parts = stem.split('-');
        parts.next()?;
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
        if normalize_pypi_name(&pieces[..index].join("-")) == project {
            return Some(pieces[index..].join("-"));
        }
    }
    stem.rsplit_once('-')
        .and_then(|(_, version)| (!version.is_empty()).then(|| version.to_string()))
}

fn filename_from_href(href_without_fragment: &str) -> Option<String> {
    href_without_fragment
        .split('?')
        .next()
        .unwrap_or(href_without_fragment)
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .map(ToOwned::to_owned)
}

fn split_fragment(href: &str) -> (&str, Option<&str>) {
    if let Some((url, fragment)) = href.split_once('#') {
        (url, Some(&href[url.len()..url.len() + fragment.len() + 1]))
    } else {
        (href, None)
    }
}

fn hashes_from_fragment(fragment: Option<&str>) -> ArtifactHashes {
    let mut hashes = ArtifactHashes::default();
    if let Some(fragment) = fragment.and_then(|value| value.strip_prefix("#sha256=")) {
        hashes.sha256 = Some(fragment.to_string());
    }
    hashes
}

fn resolve_simple_href(config: &Config, project: &str, href_without_fragment: &str) -> String {
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

fn attr_value(opening: &str, name: &str) -> Option<String> {
    let bytes = opening.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let name_start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'-' | b'_'))
        {
            index += 1;
        }
        if name_start == index {
            index += 1;
            continue;
        }
        let attr_name = &opening[name_start..index];
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            return None;
        }
        let value = if matches!(bytes[index], b'"' | b'\'') {
            let quote = bytes[index];
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != quote {
                index += 1;
            }
            let value = opening[value_start..index].to_string();
            index += usize::from(index < bytes.len());
            value
        } else {
            let value_start = index;
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() && bytes[index] != b'>'
            {
                index += 1;
            }
            opening[value_start..index].to_string()
        };
        if attr_name.eq_ignore_ascii_case(name) {
            return Some(value);
        }
    }
    None
}

fn replace_href(anchor: &str, new_href: &str) -> String {
    let Some(open_end) = anchor.find('>').map(|index| index + 1) else {
        return anchor.to_string();
    };
    let opening = &anchor[..open_end];
    let Some(href_start) = opening.to_ascii_lowercase().find("href") else {
        return anchor.to_string();
    };
    let Some(equal_relative) = opening[href_start..].find('=') else {
        return anchor.to_string();
    };
    let value_start = href_start + equal_relative + 1;
    let bytes = opening.as_bytes();
    let mut index = value_start;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if index >= bytes.len() {
        return anchor.to_string();
    }
    let (replace_start, replace_end, quote) = if matches!(bytes[index], b'"' | b'\'') {
        let quote = bytes[index] as char;
        let replace_start = index + 1;
        let replace_end = opening[replace_start..]
            .find(quote)
            .map(|relative| replace_start + relative)
            .unwrap_or(opening.len());
        (replace_start, replace_end, None)
    } else {
        let replace_start = index;
        let replace_end = opening[replace_start..]
            .find(|ch: char| ch.is_ascii_whitespace() || ch == '>')
            .map(|relative| replace_start + relative)
            .unwrap_or(opening.len());
        (replace_start, replace_end, Some('"'))
    };

    let mut replaced = String::with_capacity(anchor.len() + new_href.len());
    replaced.push_str(&anchor[..replace_start]);
    if let Some(quote) = quote {
        replaced.push(quote);
    }
    replaced.push_str(new_href);
    if let Some(quote) = quote {
        replaced.push(quote);
    }
    replaced.push_str(&anchor[replace_end..]);
    replaced
}

fn parse_pypi_time(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

#[derive(Debug, Error)]
pub enum PypiError {
    #[error("PyPI upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("PyPI JSON handling failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid PyPI Simple HTML: {0}")]
    InvalidSimpleHtml(String),
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
    use crate::config::BlocklistEntry;
    use crate::malicious::{MaliciousError, MaliciousHit};
    use crate::policy::{Decision, DecisionReason};
    use chrono::Duration as ChronoDuration;
    use std::cell::Cell;
    use std::collections::HashMap;

    struct StaticSimple {
        root: String,
        projects: HashMap<String, String>,
    }

    impl StaticSimple {
        fn new(project: &str, html: &str) -> Self {
            Self {
                root: "<html><body><a href=\"requests/\">requests</a></body></html>".to_string(),
                projects: HashMap::from([(normalize_pypi_name(project), html.to_string())]),
            }
        }
    }

    impl PypiSimpleProvider for StaticSimple {
        fn fetch_simple_root(&self) -> Result<String, PypiError> {
            Ok(self.root.clone())
        }

        fn fetch_project_simple(&self, project: &str) -> Result<String, PypiError> {
            self.projects
                .get(&normalize_pypi_name(project))
                .cloned()
                .ok_or_else(|| PypiError::InvalidSimpleHtml(format!("missing {project}")))
        }
    }

    struct CleanChecker {
        calls: Cell<u32>,
    }

    impl CleanChecker {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }
    }

    impl MaliciousChecker for CleanChecker {
        fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            self.calls.set(self.calls.get() + 1);
            Ok(Vec::new())
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn simple_fixture() -> &'static str {
        r#"<html><body>
<a href="https://files.example/packages/demo-1.0.0.tar.gz#sha256=abc" data-upload-time="2026-06-01T00:00:00Z">demo-1.0.0.tar.gz</a>
<a href="https://files.example/packages/demo-1.0.1.tar.gz#sha256=bad" data-upload-time="2026-06-01T00:00:00Z">demo-1.0.1.tar.gz</a>
<a href="../../packages/demo-2.0.0-py3-none-any.whl#sha256=new" data-upload-time="2026-07-05T00:00:00Z">demo-2.0.0-py3-none-any.whl</a>
</body></html>"#
    }

    #[test]
    fn pypi_simple_filters_blocked_and_too_young_files_and_rewrites_allowed_links() {
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

        let response =
            simple_project_response(&config, &upstream, &checker, "Demo", now()).unwrap();
        let body = String::from_utf8(response.body).unwrap();

        assert_eq!(response.status, 200);
        assert!(body.contains(
            "https://proxy.example/pypi/packages/demo/1.0.0/demo-1.0.0.tar.gz#sha256=abc"
        ));
        assert!(!body.contains("demo-1.0.1.tar.gz"));
        assert!(!body.contains("demo-2.0.0-py3-none-any.whl"));
        assert_eq!(checker.calls.get(), 3);
    }

    #[test]
    fn pypi_artifact_allowed_file_redirects_to_upstream() {
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
        .unwrap();

        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            vec![(
                "location".to_string(),
                "https://files.example/packages/demo-1.0.0.tar.gz".to_string()
            )]
        );
        assert_eq!(checker.calls.get(), 1);
    }

    #[test]
    fn pypi_artifact_blocked_file_returns_structured_403() {
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
        .unwrap();
        let body: Decision = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status, 403);
        assert!(!body.allowed);
        assert_eq!(body.reason, DecisionReason::ManuallyBlocked);
        assert_eq!(body.package, "pypi:demo@1.0.0");
    }

    #[test]
    fn pypi_simple_root_returns_upstream_html() {
        let upstream = StaticSimple::new("demo", simple_fixture());
        let response = simple_root_response(&upstream).unwrap();

        assert_eq!(response.status, 200);
        assert!(String::from_utf8(response.body)
            .unwrap()
            .contains("requests"));
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
