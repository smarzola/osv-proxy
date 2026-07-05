use crate::config::Config;
use crate::malicious::{MaliciousChecker, OsvHttpClient};
use crate::npm::{self, NpmMetadataProvider, NpmRegistryClient};
use crate::pypi::{self, PypiSimpleClient, PypiSimpleProvider};
use crate::response::RegistryResponse;
use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Uri};
use axum::routing::any;
use axum::Router;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::timeout::TimeoutLayer;

const REQUEST_BODY_LIMIT_BYTES: usize = 8192;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.server.listen).await?;
    println!("serving osv-proxy on {}", listener.local_addr()?);
    serve_listener(listener, config).await
}

pub async fn serve_listener(listener: TcpListener, config: Config) -> anyhow::Result<()> {
    axum::serve(listener, router(config)).await?;
    Ok(())
}

pub fn router(config: Config) -> Router {
    Router::new()
        .fallback(any(registry_handler))
        .with_state(Arc::new(config))
        .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
}

async fn registry_handler(
    State(config): State<Arc<Config>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response<Body> {
    let method = method.as_str().to_string();
    let path = uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or_else(|| uri.path())
        .to_string();
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let response = route_request_with_accept(&config, &method, &path, accept.as_deref()).await;

    registry_response_into_http(response)
}

pub async fn route_request(config: &Config, method: &str, path: &str) -> RegistryResponse {
    route_request_with_accept(config, method, path, None).await
}

pub async fn route_request_with_accept(
    config: &Config,
    method: &str,
    path: &str,
    accept: Option<&str>,
) -> RegistryResponse {
    let npm_upstream = NpmRegistryClient::new(&config.upstreams.npm.registry_url);
    let pypi_upstream = PypiSimpleClient::new(&config.upstreams.pypi.simple_url);
    let checker = OsvHttpClient::new(&config.policy.malicious.osv_api_url);
    route_request_with_dependencies(
        config,
        method,
        path,
        Utc::now(),
        RouteDependencies {
            checker: &checker,
            npm_upstream: &npm_upstream,
            pypi_upstream: &pypi_upstream,
            accept,
        },
    )
    .await
}

pub async fn route_request_with_upstream(
    config: &Config,
    method: &str,
    path: &str,
    now: DateTime<Utc>,
    checker: &dyn MaliciousChecker,
    upstream: &dyn NpmMetadataProvider,
) -> RegistryResponse {
    route_request_with_upstreams(
        config,
        method,
        path,
        now,
        checker,
        upstream,
        &MissingPypiUpstream,
    )
    .await
}

pub async fn route_request_with_upstreams(
    config: &Config,
    method: &str,
    path: &str,
    now: DateTime<Utc>,
    checker: &dyn MaliciousChecker,
    npm_upstream: &dyn NpmMetadataProvider,
    pypi_upstream: &dyn PypiSimpleProvider,
) -> RegistryResponse {
    route_request_with_dependencies(
        config,
        method,
        path,
        now,
        RouteDependencies {
            checker,
            npm_upstream,
            pypi_upstream,
            accept: None,
        },
    )
    .await
}

struct RouteDependencies<'a> {
    checker: &'a dyn MaliciousChecker,
    npm_upstream: &'a dyn NpmMetadataProvider,
    pypi_upstream: &'a dyn PypiSimpleProvider,
    accept: Option<&'a str>,
}

async fn route_request_with_dependencies(
    config: &Config,
    method: &str,
    path: &str,
    now: DateTime<Utc>,
    dependencies: RouteDependencies<'_>,
) -> RegistryResponse {
    if method != "GET" {
        return simple_response(405, "method not allowed");
    }

    match parse_npm_route(path) {
        Some(NpmRoute::Metadata { package }) => npm::metadata_response(
            config,
            dependencies.npm_upstream,
            dependencies.checker,
            &package,
            now,
        )
        .await
        .unwrap_or_else(|err| npm::error_response(&err)),
        Some(NpmRoute::Artifact { package, tarball }) => npm::artifact_response(
            config,
            dependencies.npm_upstream,
            dependencies.checker,
            &package,
            &tarball,
            now,
        )
        .await
        .unwrap_or_else(|err| npm::error_response(&err)),
        None => match parse_pypi_route(path) {
            Some(PypiRoute::SimpleRoot) => {
                pypi::simple_root_response(config, dependencies.pypi_upstream)
                    .await
                    .unwrap_or_else(|err| pypi::error_response(&err))
            }
            Some(PypiRoute::SimpleProject { project }) => pypi::simple_project_response_for_accept(
                config,
                dependencies.pypi_upstream,
                dependencies.checker,
                &project,
                now,
                dependencies.accept,
            )
            .await
            .unwrap_or_else(|err| pypi::error_response(&err)),
            Some(PypiRoute::Artifact {
                project,
                version,
                filename,
            }) => pypi::artifact_response(
                config,
                dependencies.pypi_upstream,
                dependencies.checker,
                &project,
                &version,
                &filename,
                now,
            )
            .await
            .unwrap_or_else(|err| pypi::error_response(&err)),
            None => simple_response(404, "not found"),
        },
    }
}

fn registry_response_into_http(response: RegistryResponse) -> Response<Body> {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    let headers = builder
        .headers_mut()
        .expect("headers are available before response body is built");
    for (name, value) in response.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(name, value);
        }
    }
    builder
        .body(Body::from(response.body))
        .expect("registry response should convert to HTTP response")
}

fn simple_response(status: u16, message: &str) -> RegistryResponse {
    let body = serde_json::json!({ "message": message });
    RegistryResponse::json(status, &body).expect("static server response should serialize")
}

struct MissingPypiUpstream;

#[async_trait]
impl PypiSimpleProvider for MissingPypiUpstream {
    async fn fetch_simple_root(&self) -> Result<String, pypi::PypiError> {
        Err(pypi::PypiError::InvalidSimpleJson(
            "PyPI upstream was not provided".to_string(),
        ))
    }

    async fn fetch_project_json(
        &self,
        _project: &str,
    ) -> Result<pypi::SimpleProject, pypi::PypiError> {
        Err(pypi::PypiError::InvalidSimpleJson(
            "PyPI upstream was not provided".to_string(),
        ))
    }
}

#[cfg(test)]
fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().skip(1).find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NpmRoute {
    Metadata { package: String },
    Artifact { package: String, tarball: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PypiRoute {
    SimpleRoot,
    SimpleProject {
        project: String,
    },
    Artifact {
        project: String,
        version: String,
        filename: String,
    },
}

fn parse_pypi_route(path: &str) -> Option<PypiRoute> {
    let path_without_query = path.split('?').next().unwrap_or(path);
    if path_without_query == "/pypi/simple/" || path_without_query == "/pypi/simple" {
        return Some(PypiRoute::SimpleRoot);
    }

    if let Some(rest) = path_without_query.strip_prefix("/pypi/simple/") {
        let project = rest.trim_end_matches('/');
        if !project.is_empty() && !project.contains('/') {
            let project = percent_decode_segment(project)?;
            return Some(PypiRoute::SimpleProject {
                project: crate::artifact::normalize_pypi_name(&project),
            });
        }
    }

    let rest = path_without_query.strip_prefix("/pypi/packages/")?;
    let segments = rest
        .split('/')
        .map(percent_decode_segment)
        .collect::<Option<Vec<_>>>()?;
    match segments.as_slice() {
        [project, version, filename]
            if !project.is_empty() && !version.is_empty() && !filename.is_empty() =>
        {
            Some(PypiRoute::Artifact {
                project: crate::artifact::normalize_pypi_name(project),
                version: version.to_string(),
                filename: filename.to_string(),
            })
        }
        _ => None,
    }
}

fn parse_npm_route(path: &str) -> Option<NpmRoute> {
    let path_without_query = path.split('?').next().unwrap_or(path);
    let rest = path_without_query.strip_prefix("/npm/")?;
    let segments = rest
        .split('/')
        .map(percent_decode_segment)
        .collect::<Option<Vec<_>>>()?;

    match segments.as_slice() {
        [package] if !package.is_empty() => Some(NpmRoute::Metadata {
            package: package.to_string(),
        }),
        [package, dash, tarball] if !package.is_empty() && dash == "-" && !tarball.is_empty() => {
            Some(NpmRoute::Artifact {
                package: package.to_string(),
                tarball: tarball.to_string(),
            })
        }
        [scope, package] if scope.starts_with('@') && !package.is_empty() => {
            Some(NpmRoute::Metadata {
                package: format!("{scope}/{package}"),
            })
        }
        [scope, package, dash, tarball]
            if scope.starts_with('@')
                && !package.is_empty()
                && dash == "-"
                && !tarball.is_empty() =>
        {
            Some(NpmRoute::Artifact {
                package: format!("{scope}/{package}"),
                tarball: tarball.to_string(),
            })
        }
        _ => None,
    }
}

fn percent_decode_segment(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            output.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, Ecosystem};
    use crate::config::BlocklistEntry;
    use crate::malicious::{MaliciousError, MaliciousHit};
    use crate::npm::NpmError;
    use crate::pypi::{SimpleFile, SimpleProject};
    use chrono::Duration as ChronoDuration;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    struct StaticUpstream {
        metadata: HashMap<String, Value>,
    }

    impl StaticUpstream {
        fn with(package: &str, metadata: Value) -> Self {
            Self {
                metadata: HashMap::from([(package.to_string(), metadata)]),
            }
        }
    }

    #[async_trait]
    impl NpmMetadataProvider for StaticUpstream {
        async fn fetch_package_metadata(&self, package: &str) -> Result<Value, NpmError> {
            self.metadata.get(package).cloned().ok_or_else(|| {
                NpmError::InvalidMetadata(format!("missing static metadata for {package}"))
            })
        }
    }

    struct StaticPypiUpstream {
        root: String,
        projects: HashMap<String, SimpleProject>,
    }

    impl StaticPypiUpstream {
        fn with(project: &str, simple: SimpleProject) -> Self {
            Self {
                root: "<html><body><a href=\"demo/\">demo</a></body></html>".to_string(),
                projects: HashMap::from([(crate::artifact::normalize_pypi_name(project), simple)]),
            }
        }
    }

    #[async_trait]
    impl PypiSimpleProvider for StaticPypiUpstream {
        async fn fetch_simple_root(&self) -> Result<String, pypi::PypiError> {
            Ok(self.root.clone())
        }

        async fn fetch_project_json(
            &self,
            project: &str,
        ) -> Result<SimpleProject, pypi::PypiError> {
            self.projects
                .get(&crate::artifact::normalize_pypi_name(project))
                .cloned()
                .ok_or_else(|| pypi::PypiError::InvalidSimpleJson(format!("missing {project}")))
        }
    }

    struct CleanChecker;

    #[async_trait]
    impl MaliciousChecker for CleanChecker {
        async fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            Ok(Vec::new())
        }
    }

    struct MaliciousPackageChecker {
        package: String,
    }

    impl MaliciousPackageChecker {
        fn new(package: &str) -> Self {
            Self {
                package: package.to_string(),
            }
        }
    }

    #[async_trait]
    impl MaliciousChecker for MaliciousPackageChecker {
        async fn check(&self, artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            if artifact.identity() == self.package {
                Ok(vec![MaliciousHit {
                    osv_id: "MAL-2026-000001".to_string(),
                    summary: Some("malicious fixture".to_string()),
                    source: "osv".to_string(),
                    modified: None,
                }])
            } else {
                Ok(Vec::new())
            }
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

    fn pypi_file(filename: &str, url: &str, upload_time: Option<DateTime<Utc>>) -> SimpleFile {
        SimpleFile {
            filename: filename.to_string(),
            url: url.to_string(),
            hashes: BTreeMap::from([("sha256".to_string(), format!("hash-{filename}"))]),
            requires_python: None,
            dist_info_metadata: None,
            gpg_sig: None,
            yanked: None,
            upload_time,
            extra: BTreeMap::new(),
        }
    }

    fn pypi_simple_fixture() -> SimpleProject {
        SimpleProject {
            meta: BTreeMap::from([("api-version".to_string(), json!("1.1"))]),
            name: "demo".to_string(),
            versions: vec![
                "1.0.0".to_string(),
                "1.0.1".to_string(),
                "2.0.0".to_string(),
            ],
            files: vec![
                pypi_file(
                    "demo-1.0.0.tar.gz",
                    "https://files.example/packages/demo-1.0.0.tar.gz",
                    Some(old_time()),
                ),
                pypi_file(
                    "demo-1.0.1.tar.gz",
                    "https://files.example/packages/demo-1.0.1.tar.gz",
                    Some(old_time()),
                ),
                pypi_file(
                    "demo-2.0.0-py3-none-any.whl",
                    "https://files.example/packages/demo-2.0.0-py3-none-any.whl",
                    Some(new_time()),
                ),
            ],
        }
    }

    #[tokio::test]
    async fn parses_documented_npm_routes() {
        assert_eq!(
            parse_npm_route("/npm/lodash"),
            Some(NpmRoute::Metadata {
                package: "lodash".to_string()
            })
        );
        assert_eq!(
            parse_npm_route("/npm/@babel/core"),
            Some(NpmRoute::Metadata {
                package: "@babel/core".to_string()
            })
        );
        assert_eq!(
            parse_npm_route("/npm/lodash/-/lodash-4.17.21.tgz"),
            Some(NpmRoute::Artifact {
                package: "lodash".to_string(),
                tarball: "lodash-4.17.21.tgz".to_string()
            })
        );
        assert_eq!(
            parse_npm_route("/npm/@babel/core/-/core-7.24.0.tgz"),
            Some(NpmRoute::Artifact {
                package: "@babel/core".to_string(),
                tarball: "core-7.24.0.tgz".to_string()
            })
        );
    }

    #[tokio::test]
    async fn parses_encoded_scoped_npm_metadata_route() {
        assert_eq!(
            parse_npm_route("/npm/@babel%2Fcore?write=true"),
            Some(NpmRoute::Metadata {
                package: "@babel/core".to_string()
            })
        );
    }

    #[tokio::test]
    async fn parses_documented_pypi_routes() {
        assert_eq!(
            parse_pypi_route("/pypi/simple/"),
            Some(PypiRoute::SimpleRoot)
        );
        assert_eq!(
            parse_pypi_route("/pypi/simple/My_Package.Name/"),
            Some(PypiRoute::SimpleProject {
                project: "my-package-name".to_string()
            })
        );
        assert_eq!(
            parse_pypi_route("/pypi/packages/My_Package.Name/1.0.0/demo-1.0.0.tar.gz"),
            Some(PypiRoute::Artifact {
                project: "my-package-name".to_string(),
                version: "1.0.0".to_string(),
                filename: "demo-1.0.0.tar.gz".to_string()
            })
        );
    }

    #[tokio::test]
    async fn routes_npm_metadata_with_mocked_upstream() {
        let config = Config::default();
        let upstream = StaticUpstream::with(
            "lodash",
            json!({
                "name": "lodash",
                "dist-tags": { "latest": "4.17.21" },
                "time": { "4.17.21": "2026-06-01T00:00:00Z" },
                "versions": {
                    "4.17.21": {
                        "name": "lodash",
                        "version": "4.17.21",
                        "dist": {
                            "tarball": "https://registry.example/lodash/-/lodash-4.17.21.tgz"
                        }
                    }
                }
            }),
        );

        let response = route_request_with_upstream(
            &config,
            "GET",
            "/npm/lodash",
            now(),
            &CleanChecker,
            &upstream,
        )
        .await;

        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            body["versions"]["4.17.21"]["dist"]["tarball"],
            "http://127.0.0.1:8080/npm/lodash/-/lodash-4.17.21.tgz"
        );
    }

    #[tokio::test]
    async fn routes_npm_artifact_with_mocked_upstream() {
        let config = Config::default();
        let upstream = StaticUpstream::with(
            "@babel/core",
            json!({
                "name": "@babel/core",
                "time": { "7.24.0": "2026-06-01T00:00:00Z" },
                "versions": {
                    "7.24.0": {
                        "name": "@babel/core",
                        "version": "7.24.0",
                        "dist": {
                            "tarball": "https://registry.example/@babel/core/-/core-7.24.0.tgz"
                        }
                    }
                }
            }),
        );

        let response = route_request_with_upstream(
            &config,
            "GET",
            "/npm/@babel/core/-/core-7.24.0.tgz",
            now(),
            &CleanChecker,
            &upstream,
        )
        .await;

        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            vec![(
                "location".to_string(),
                "https://registry.example/@babel/core/-/core-7.24.0.tgz".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn routes_pypi_simple_project_with_mocked_upstream() {
        let config = Config::default();
        let npm_upstream = StaticUpstream::with("unused", json!({}));
        let mut simple = pypi_simple_fixture();
        simple.files = vec![pypi_file(
            "demo-1.0.0.tar.gz",
            "https://files.example/demo-1.0.0.tar.gz",
            Some(old_time()),
        )];
        simple.versions = vec!["1.0.0".to_string()];
        let pypi_upstream = StaticPypiUpstream::with("demo", simple);

        let response = route_request_with_upstreams(
            &config,
            "GET",
            "/pypi/simple/Demo/",
            now(),
            &CleanChecker,
            &npm_upstream,
            &pypi_upstream,
        )
        .await;
        let body = String::from_utf8(response.body).unwrap();

        assert_eq!(response.status, 200);
        assert!(body.contains(
            "http://127.0.0.1:8080/pypi/packages/demo/1.0.0/demo-1.0.0.tar.gz#sha256=hash-demo-1.0.0.tar.gz"
        ));
    }

    #[tokio::test]
    async fn routes_pypi_simple_json_when_client_accepts_json() {
        let config = Config::default();
        let npm_upstream = StaticUpstream::with("unused", json!({}));
        let pypi_upstream = StaticPypiUpstream::with("demo", pypi_simple_fixture());

        let response = route_request_with_dependencies(
            &config,
            "GET",
            "/pypi/simple/Demo/",
            now(),
            RouteDependencies {
                checker: &CleanChecker,
                npm_upstream: &npm_upstream,
                pypi_upstream: &pypi_upstream,
                accept: Some("application/vnd.pypi.simple.v1+json"),
            },
        )
        .await;
        let body: Value = serde_json::from_slice(&response.body).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(name, _)| name == "content-type")
                .map(|(_, value)| value.as_str()),
            Some("application/vnd.pypi.simple.v1+json")
        );
        assert_eq!(body["versions"], json!(["1.0.0", "1.0.1"]));
        assert_eq!(body["files"].as_array().unwrap().len(), 2);
        assert_eq!(
            body["files"][0]["url"],
            "http://127.0.0.1:8080/pypi/packages/demo/1.0.0/demo-1.0.0.tar.gz"
        );
        assert!(!body.to_string().contains("demo-2.0.0-py3-none-any.whl"));
    }

    #[tokio::test]
    async fn routes_pypi_artifact_with_mocked_upstream() {
        let config = Config::default();
        let npm_upstream = StaticUpstream::with("unused", json!({}));
        let mut simple = pypi_simple_fixture();
        simple.files = vec![pypi_file(
            "demo-1.0.0.tar.gz",
            "https://files.example/demo-1.0.0.tar.gz",
            Some(old_time()),
        )];
        simple.versions = vec!["1.0.0".to_string()];
        let pypi_upstream = StaticPypiUpstream::with("demo", simple);

        let response = route_request_with_upstreams(
            &config,
            "GET",
            "/pypi/packages/demo/1.0.0/demo-1.0.0.tar.gz",
            now(),
            &CleanChecker,
            &npm_upstream,
            &pypi_upstream,
        )
        .await;

        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            vec![(
                "location".to_string(),
                "https://files.example/demo-1.0.0.tar.gz".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn e2e_npm_route_filters_metadata_redirects_allowed_and_blocks_direct_artifact() {
        let mut config = Config::default();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Npm,
            name: "demo".to_string(),
            versions: vec!["1.0.1".to_string()],
            reason: "known bad".to_string(),
        });
        let npm_upstream = StaticUpstream::with(
            "demo",
            json!({
                "name": "demo",
                "dist-tags": {
                    "latest": "1.0.1",
                    "stable": "1.0.0"
                },
                "time": {
                    "1.0.0": "2026-06-01T00:00:00Z",
                    "1.0.1": "2026-06-01T00:00:00Z"
                },
                "versions": {
                    "1.0.0": {
                        "name": "demo",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": "https://registry.example/demo/-/demo-1.0.0.tgz"
                        }
                    },
                    "1.0.1": {
                        "name": "demo",
                        "version": "1.0.1",
                        "dist": {
                            "tarball": "https://registry.example/demo/-/demo-1.0.1.tgz"
                        }
                    }
                }
            }),
        );

        let metadata_response = route_request_with_upstream(
            &config,
            "GET",
            "/npm/demo",
            now(),
            &CleanChecker,
            &npm_upstream,
        )
        .await;
        assert_eq!(metadata_response.status, 200);
        let metadata: Value = serde_json::from_slice(&metadata_response.body).unwrap();
        assert!(metadata["versions"]
            .as_object()
            .unwrap()
            .contains_key("1.0.0"));
        assert!(!metadata["versions"]
            .as_object()
            .unwrap()
            .contains_key("1.0.1"));
        assert_eq!(
            metadata["versions"]["1.0.0"]["dist"]["tarball"],
            "http://127.0.0.1:8080/npm/demo/-/demo-1.0.0.tgz"
        );
        assert_eq!(metadata["dist-tags"], json!({ "stable": "1.0.0" }));

        let allowed_artifact_response = route_request_with_upstream(
            &config,
            "GET",
            "/npm/demo/-/demo-1.0.0.tgz",
            now(),
            &CleanChecker,
            &npm_upstream,
        )
        .await;
        assert_eq!(allowed_artifact_response.status, 302);
        assert_eq!(
            allowed_artifact_response.headers,
            vec![(
                "location".to_string(),
                "https://registry.example/demo/-/demo-1.0.0.tgz".to_string()
            )]
        );

        let blocked_artifact_response = route_request_with_upstream(
            &config,
            "GET",
            "/npm/demo/-/demo-1.0.1.tgz",
            now(),
            &CleanChecker,
            &npm_upstream,
        )
        .await;
        let blocked_body: Value = serde_json::from_slice(&blocked_artifact_response.body).unwrap();
        assert_eq!(blocked_artifact_response.status, 403);
        assert_eq!(blocked_body["allowed"], false);
        assert_eq!(blocked_body["package"], "npm:demo@1.0.1");
    }

    #[tokio::test]
    async fn e2e_npm_route_filters_malicious_metadata_and_blocks_artifact() {
        let config = Config::default();
        let npm_upstream = StaticUpstream::with(
            "demo",
            json!({
                "name": "demo",
                "dist-tags": { "latest": "1.0.1", "stable": "1.0.0" },
                "time": {
                    "1.0.0": "2026-06-01T00:00:00Z",
                    "1.0.1": "2026-06-01T00:00:00Z"
                },
                "versions": {
                    "1.0.0": {
                        "name": "demo",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": "https://registry.example/demo/-/demo-1.0.0.tgz"
                        }
                    },
                    "1.0.1": {
                        "name": "demo",
                        "version": "1.0.1",
                        "dist": {
                            "tarball": "https://registry.example/demo/-/demo-1.0.1.tgz"
                        }
                    }
                }
            }),
        );
        let checker = MaliciousPackageChecker::new("npm:demo@1.0.1");

        let metadata_response = route_request_with_upstream(
            &config,
            "GET",
            "/npm/demo",
            now(),
            &checker,
            &npm_upstream,
        )
        .await;
        let metadata: Value = serde_json::from_slice(&metadata_response.body).unwrap();

        assert_eq!(metadata_response.status, 200);
        assert!(metadata["versions"]
            .as_object()
            .unwrap()
            .contains_key("1.0.0"));
        assert!(!metadata["versions"]
            .as_object()
            .unwrap()
            .contains_key("1.0.1"));
        assert_eq!(metadata["dist-tags"], json!({ "stable": "1.0.0" }));

        let blocked_artifact_response = route_request_with_upstream(
            &config,
            "GET",
            "/npm/demo/-/demo-1.0.1.tgz",
            now(),
            &checker,
            &npm_upstream,
        )
        .await;
        let blocked_body: Value = serde_json::from_slice(&blocked_artifact_response.body).unwrap();
        assert_eq!(blocked_artifact_response.status, 403);
        assert_eq!(blocked_body["reason"], "malicious");
        assert_eq!(blocked_body["rule_id"], "MAL-2026-000001");
    }

    #[tokio::test]
    async fn e2e_pypi_route_filters_simple_redirects_allowed_and_blocks_direct_artifact() {
        let mut config = Config::default();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Pypi,
            name: "Demo".to_string(),
            versions: vec!["1.0.1".to_string()],
            reason: "known bad".to_string(),
        });
        let npm_upstream = StaticUpstream::with("unused", json!({}));
        let pypi_upstream = StaticPypiUpstream::with("Demo", pypi_simple_fixture());

        let simple_response = route_request_with_upstreams(
            &config,
            "GET",
            "/pypi/simple/Demo/",
            now(),
            &CleanChecker,
            &npm_upstream,
            &pypi_upstream,
        )
        .await;
        assert_eq!(simple_response.status, 200);
        let simple_body = String::from_utf8(simple_response.body).unwrap();
        assert!(simple_body.contains(
            "http://127.0.0.1:8080/pypi/packages/demo/1.0.0/demo-1.0.0.tar.gz#sha256=hash-demo-1.0.0.tar.gz"
        ));
        assert!(!simple_body.contains("demo-1.0.1.tar.gz"));
        assert!(!simple_body.contains("demo-2.0.0-py3-none-any.whl"));

        let allowed_artifact_response = route_request_with_upstreams(
            &config,
            "GET",
            "/pypi/packages/demo/1.0.0/demo-1.0.0.tar.gz",
            now(),
            &CleanChecker,
            &npm_upstream,
            &pypi_upstream,
        )
        .await;
        assert_eq!(allowed_artifact_response.status, 302);
        assert_eq!(
            allowed_artifact_response.headers,
            vec![(
                "location".to_string(),
                "https://files.example/packages/demo-1.0.0.tar.gz".to_string()
            )]
        );

        let blocked_artifact_response = route_request_with_upstreams(
            &config,
            "GET",
            "/pypi/packages/demo/1.0.1/demo-1.0.1.tar.gz",
            now(),
            &CleanChecker,
            &npm_upstream,
            &pypi_upstream,
        )
        .await;
        let blocked_body: Value = serde_json::from_slice(&blocked_artifact_response.body).unwrap();
        assert_eq!(blocked_artifact_response.status, 403);
        assert_eq!(blocked_body["allowed"], false);
        assert_eq!(blocked_body["package"], "pypi:demo@1.0.1");
    }

    #[tokio::test]
    async fn e2e_pypi_route_filters_malicious_json_and_blocks_artifact() {
        let config = Config::default();
        let npm_upstream = StaticUpstream::with("unused", json!({}));
        let pypi_upstream = StaticPypiUpstream::with("Demo", pypi_simple_fixture());
        let checker = MaliciousPackageChecker::new("pypi:demo@1.0.1");

        let simple_response = route_request_with_dependencies(
            &config,
            "GET",
            "/pypi/simple/Demo/",
            now(),
            RouteDependencies {
                checker: &checker,
                npm_upstream: &npm_upstream,
                pypi_upstream: &pypi_upstream,
                accept: Some("application/vnd.pypi.simple.v1+json"),
            },
        )
        .await;
        let simple_body: Value = serde_json::from_slice(&simple_response.body).unwrap();

        assert_eq!(simple_response.status, 200);
        assert_eq!(simple_body["versions"], json!(["1.0.0"]));
        assert_eq!(simple_body["files"].as_array().unwrap().len(), 1);
        assert!(!simple_body.to_string().contains("demo-1.0.1.tar.gz"));
        assert!(!simple_body
            .to_string()
            .contains("demo-2.0.0-py3-none-any.whl"));

        let blocked_artifact_response = route_request_with_upstreams(
            &config,
            "GET",
            "/pypi/packages/demo/1.0.1/demo-1.0.1.tar.gz",
            now(),
            &checker,
            &npm_upstream,
            &pypi_upstream,
        )
        .await;
        let blocked_body: Value = serde_json::from_slice(&blocked_artifact_response.body).unwrap();

        assert_eq!(blocked_artifact_response.status, 403);
        assert_eq!(blocked_body["reason"], "malicious");
        assert_eq!(blocked_body["rule_id"], "MAL-2026-000001");
    }

    #[tokio::test]
    async fn method_mismatch_returns_405() {
        let response = route_request_with_upstream(
            &Config::default(),
            "POST",
            "/npm/lodash",
            now(),
            &CleanChecker,
            &StaticUpstream::with("lodash", json!({})),
        )
        .await;
        assert_eq!(response.status, 405);
    }

    #[tokio::test]
    async fn parses_accept_header_case_insensitively() {
        let request = "GET /pypi/simple/demo/ HTTP/1.1\r\nHost: localhost\r\nAccept: application/vnd.pypi.simple.v1+json\r\n\r\n";
        assert_eq!(
            header_value(request, "accept").as_deref(),
            Some("application/vnd.pypi.simple.v1+json")
        );
    }

    #[tokio::test]
    async fn router_returns_405_without_binding_live_port() {
        let response = router(Config::default())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/npm/lodash")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn idle_connection_does_not_block_unrelated_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            serve_listener(listener, Config::default()).await.unwrap();
        });

        let _idle_connection = tokio::net::TcpStream::connect(addr).await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"GET /missing HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            response
        })
        .await
        .unwrap();

        server.abort();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn clean_checker_uses_npm_artifacts() {
        let artifact = Artifact::package(Ecosystem::Npm, "lodash", "4.17.21", None);
        assert_eq!(artifact.identity(), "npm:lodash@4.17.21");
    }
}
