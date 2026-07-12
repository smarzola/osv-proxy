use crate::artifacts::{ArtifactDeliveryClient, ArtifactDeliveryOptions};
use crate::cargo::{self, CargoRegistryClient};
use crate::config::{Config, LocalOsvConfig, OsvSource};
use crate::go::{self, GoProxyClient};
use crate::malicious::{
    ALL_OSV_ECOSYSTEMS, HttpOsvDumpClient, MaliciousChecker, OsvDumpClient,
    configured_malicious_checker, configured_malicious_checker_with_budgets, sync_osv_ecosystems,
};
use crate::maven::{self, MavenRepositoryClient, MetadataChecksum};
use crate::npm::{self, NpmMetadataProvider, NpmRegistryClient};
use crate::nuget::{self, NugetClient};
use crate::pypi::{self, PypiSimpleClient, PypiSimpleProvider};
use crate::response::RegistryResponse;
use crate::rubygems::{self, CompactIndexProvider, RubyGemsClient};
use crate::runtime::{BudgetError, RuntimeBudgets, hold_permits, track_request_overload};
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, Response, Uri, header};
use axum::routing::any;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const REQUEST_BODY_LIMIT_BYTES: usize = 8192;
const BACKGROUND_RETRY_POLICY: BackgroundRetryPolicy = BackgroundRetryPolicy {
    initial: Duration::from_secs(5),
    maximum: Duration::from_secs(5 * 60),
};

#[derive(Clone, Copy)]
struct BackgroundRetryPolicy {
    initial: Duration,
    maximum: Duration,
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.server.bind).await?;
    println!("serving osv-proxy on {}", listener.local_addr()?);
    serve_listener(listener, config).await
}

pub async fn serve_listener(listener: TcpListener, config: Config) -> anyhow::Result<()> {
    let budgets = Arc::new(RuntimeBudgets::new(&config.limits));
    let _background_sync = start_background_osv_sync_if_enabled(&config, Arc::clone(&budgets));
    axum::serve(listener, router_with_budgets(config, budgets)).await?;
    Ok(())
}

pub fn router(config: Config) -> Router {
    let budgets = Arc::new(RuntimeBudgets::new(&config.limits));
    router_with_budgets(config, budgets)
}

fn router_with_budgets(config: Config, budgets: Arc<RuntimeBudgets>) -> Router {
    let checker = configured_malicious_checker_with_budgets(&config, Arc::clone(&budgets));
    Router::new()
        .fallback(any(registry_handler))
        .with_state(Arc::new(AppState::new(config, checker, budgets)))
        .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES))
}

struct AppState {
    config: Config,
    checker: Arc<dyn MaliciousChecker>,
    clients: RegistryClients,
    budgets: Arc<RuntimeBudgets>,
}

impl AppState {
    fn new(
        config: Config,
        checker: Arc<dyn MaliciousChecker>,
        budgets: Arc<RuntimeBudgets>,
    ) -> Self {
        let clients = RegistryClients::new(&config, Arc::clone(&budgets));
        Self {
            config,
            checker,
            clients,
            budgets,
        }
    }
}

struct RegistryClients {
    npm: NpmRegistryClient,
    pypi: PypiSimpleClient,
    go: GoProxyClient,
    cargo: CargoRegistryClient,
    delivery: ArtifactDeliveryClient,
    nuget: NugetClient,
    rubygems: RubyGemsClient,
    maven: MavenRepositoryClient,
}

impl RegistryClients {
    fn new(config: &Config, budgets: Arc<RuntimeBudgets>) -> Self {
        let delivery = ArtifactDeliveryClient::with_budgets(config, Arc::clone(&budgets));
        let nuget = NugetClient::with_delivery(config, delivery.clone());
        Self {
            npm: NpmRegistryClient::with_budgets(
                &config.upstreams.npm.registry_url,
                Arc::clone(&budgets),
            ),
            pypi: PypiSimpleClient::with_budgets(
                &config.upstreams.pypi.simple_url,
                Arc::clone(&budgets),
            ),
            go: GoProxyClient::with_budgets(&config.upstreams.go.proxy_url, Arc::clone(&budgets)),
            cargo: CargoRegistryClient::with_budgets(config, Arc::clone(&budgets)),
            delivery,
            nuget,
            rubygems: RubyGemsClient::with_budgets(
                &config.upstreams.rubygems.registry_url,
                Arc::clone(&budgets),
            ),
            maven: MavenRepositoryClient::with_budgets(
                &config.upstreams.maven.repository_url,
                budgets,
            ),
        }
    }
}

struct BackgroundSyncTask {
    handle: JoinHandle<()>,
}

impl Drop for BackgroundSyncTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn start_background_osv_sync_if_enabled(
    config: &Config,
    budgets: Arc<RuntimeBudgets>,
) -> Option<BackgroundSyncTask> {
    if config.policy.osv.source != OsvSource::Local || !config.policy.osv.local.background_sync {
        return None;
    }
    Some(spawn_background_osv_sync(
        config.policy.osv.local.clone(),
        Arc::new(HttpOsvDumpClient::with_budgets(budgets)),
    ))
}

fn spawn_background_osv_sync(
    local_config: LocalOsvConfig,
    client: Arc<dyn OsvDumpClient>,
) -> BackgroundSyncTask {
    spawn_background_osv_sync_with_policy(local_config, client, BACKGROUND_RETRY_POLICY)
}

fn spawn_background_osv_sync_with_policy(
    local_config: LocalOsvConfig,
    client: Arc<dyn OsvDumpClient>,
    retry_policy: BackgroundRetryPolicy,
) -> BackgroundSyncTask {
    let handle = tokio::spawn(async move {
        let mut requested = ALL_OSV_ECOSYSTEMS.to_vec();
        let mut consecutive_failures = 0_u32;
        loop {
            let sync_result = sync_osv_ecosystems(&local_config, client.as_ref(), &requested).await;
            let delay = match sync_result {
                Ok(report) if report.is_success() => {
                    println!(
                        "local OSV background sync completed for {} ecosystems",
                        report.ecosystems.len()
                    );
                    requested = ALL_OSV_ECOSYSTEMS.to_vec();
                    consecutive_failures = 0;
                    local_config.sync_interval
                }
                Ok(report) => {
                    requested = report.failed_ecosystems();
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    eprintln!(
                        "local OSV background sync completed with {} failures out of {} attempts",
                        report.failures.len(),
                        report.attempted()
                    );
                    background_retry_delay(
                        local_config.sync_interval,
                        consecutive_failures,
                        retry_policy,
                    )
                }
                Err(err) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    eprintln!("local OSV background sync failed: {err}");
                    background_retry_delay(
                        local_config.sync_interval,
                        consecutive_failures,
                        retry_policy,
                    )
                }
            };
            tokio::time::sleep(delay).await;
        }
    });
    BackgroundSyncTask { handle }
}

fn background_retry_delay(
    sync_interval: Duration,
    consecutive_failures: u32,
    retry_policy: BackgroundRetryPolicy,
) -> Duration {
    let exponent = consecutive_failures.saturating_sub(1).min(16);
    let multiplier = 1_u32 << exponent;
    let exponential = retry_policy
        .initial
        .checked_mul(multiplier)
        .unwrap_or(retry_policy.maximum);
    let below_normal_interval = sync_interval / 2;
    exponential
        .min(retry_policy.maximum)
        .min(below_normal_interval.max(Duration::from_millis(1)))
}

async fn registry_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response<Body> {
    let ingress = match state.budgets.try_ingress() {
        Ok(permit) => permit,
        Err(error) => return error.response(),
    };
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

    let (response, overloaded) = track_request_overload(route_http_request_with_clients(
        &state.config,
        state.checker.as_ref(),
        &state.clients,
        &method,
        &path,
        accept.as_deref(),
        &headers,
    ))
    .await;
    if overloaded {
        return BudgetError::EgressSaturated.response();
    }
    hold_permits(response, vec![ingress])
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
    let go_upstream = GoProxyClient::new(&config.upstreams.go.proxy_url);
    let checker = configured_malicious_checker(config);
    let rubygems_upstream = RubyGemsClient::new(&config.upstreams.rubygems.registry_url);
    if let Some(route) = parse_rubygems_route(path) {
        let headers = HeaderMap::new();
        return match route {
            RubyGemsRoute::Versions => rubygems_upstream
                .fetch_versions_index(None)
                .await
                .unwrap_or_else(|error| rubygems::error_response(&error)),
            RubyGemsRoute::Info { name } => rubygems::compact_info_response(
                config,
                &rubygems_upstream,
                &rubygems_upstream,
                checker.as_ref(),
                &name,
                Utc::now(),
                &headers,
            )
            .await
            .unwrap_or_else(|error| rubygems::error_response(&error)),
            RubyGemsRoute::Artifact { filename } => {
                let delivery = ArtifactDeliveryClient::for_config(config);
                match rubygems::artifact_delivery_response(
                    config,
                    &rubygems_upstream,
                    checker.as_ref(),
                    &filename,
                    Utc::now(),
                    ArtifactDeliveryOptions::new(&delivery),
                )
                .await
                {
                    Ok(response) => response.into_registry_response().await,
                    Err(error) => rubygems::error_response(&error),
                }
            }
        };
    }
    if let Some((module, route)) = go::parse_route(path) {
        let delivery = ArtifactDeliveryClient::for_config(config);
        return go::route_response(
            config,
            &go_upstream,
            checker.as_ref(),
            &module,
            route,
            Utc::now(),
            Some(ArtifactDeliveryOptions::new(&delivery)),
        )
        .await
        .unwrap_or_else(|err| go_error_response(&err));
    }
    return route_request_with_dependencies(
        config,
        method,
        path,
        Utc::now(),
        RouteDependencies {
            checker: checker.as_ref(),
            npm_upstream: &npm_upstream,
            pypi_upstream: &pypi_upstream,
            accept,
        },
    )
    .await;
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
    if let Some((module, route)) = go::parse_route(path) {
        let delivery = ArtifactDeliveryClient::for_config(config);
        let go_upstream = GoProxyClient::new(&config.upstreams.go.proxy_url);
        return go::route_response(
            config,
            &go_upstream,
            checker,
            &module,
            route,
            Utc::now(),
            Some(ArtifactDeliveryOptions::new(&delivery)),
        )
        .await
        .unwrap_or_else(|err| go_error_response(&err));
    }
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

    let cargo_upstream = CargoRegistryClient::new(config);
    match parse_cargo_route(path) {
        Some(CargoRoute::Config) => cargo::config_response(config),
        Some(CargoRoute::Index { name }) => {
            cargo::index_response(config, &cargo_upstream, dependencies.checker, &name, now)
                .await
                .unwrap_or_else(|err| cargo::error_response(&err))
        }
        Some(CargoRoute::Artifact { name, version }) => {
            let delivery = ArtifactDeliveryClient::for_config(config);
            match cargo::artifact_delivery_response(
                config,
                &cargo_upstream,
                dependencies.checker,
                &name,
                &version,
                now,
                ArtifactDeliveryOptions::new(&delivery),
            )
            .await
            {
                Ok(response) => response.into_registry_response().await,
                Err(err) => cargo::error_response(&err),
            }
        }
        None => match parse_npm_route(path) {
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
                Some(PypiRoute::SimpleProject { project }) => {
                    pypi::simple_project_response_for_accept(
                        config,
                        dependencies.pypi_upstream,
                        dependencies.checker,
                        &project,
                        now,
                        dependencies.accept,
                    )
                    .await
                    .unwrap_or_else(|err| pypi::error_response(&err))
                }
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
        },
    }
}

fn go_error_response(error: &go::GoError) -> RegistryResponse {
    let status = match error {
        go::GoError::UpstreamStatus(404 | 410) => 404,
        go::GoError::InvalidRoute(_) => 404,
        _ => 502,
    };
    RegistryResponse::json(status, &serde_json::json!({"allowed": false, "reason": "go_upstream_error", "message": error.to_string()})).expect("static Go error response")
}

fn nuget_error_response(error: crate::nuget::NugetError) -> RegistryResponse {
    let status = match &error {
        crate::nuget::NugetError::VersionNotFound(_) => 404,
        crate::nuget::NugetError::Upstream(error)
            if matches!(
                error.status().map(|status| status.as_u16()),
                Some(404 | 410)
            ) =>
        {
            404
        }
        crate::nuget::NugetError::Egress(
            crate::artifacts::ArtifactDeliveryError::UpstreamStatus(404 | 410),
        ) => 404,
        _ => 502,
    };
    RegistryResponse::json(status, &serde_json::json!({"allowed": false, "reason": "nuget_upstream_error", "message": error.to_string()})).expect("static NuGet error response")
}

#[cfg(test)]
async fn route_http_request_with_accept_and_headers(
    config: &Config,
    checker: &dyn MaliciousChecker,
    method: &str,
    path: &str,
    accept: Option<&str>,
    headers: &HeaderMap,
) -> Response<Body> {
    let clients = RegistryClients::new(config, Arc::new(RuntimeBudgets::new(&config.limits)));
    route_http_request_with_clients(config, checker, &clients, method, path, accept, headers).await
}

async fn route_http_request_with_clients(
    config: &Config,
    checker: &dyn MaliciousChecker,
    clients: &RegistryClients,
    method: &str,
    path: &str,
    accept: Option<&str>,
    headers: &HeaderMap,
) -> Response<Body> {
    let maven_request = path
        .split('?')
        .next()
        .unwrap_or(path)
        .starts_with("/maven/");
    if method != "GET" && !(method == "HEAD" && maven_request) {
        return simple_response(405, "method not allowed").into_http_response();
    }

    let npm_upstream = clients.npm.clone();
    let pypi_upstream = clients.pypi.clone();
    let go_upstream = clients.go.clone();
    let cargo_upstream = clients.cargo.clone();
    let delivery = clients.delivery.clone();
    let nuget_upstream = clients.nuget.clone();
    let rubygems_upstream = clients.rubygems.clone();
    let maven_upstream = clients.maven.clone();
    let now = Utc::now();

    if let Some((relative_path, checksum)) = parse_maven_metadata_route(path) {
        let mut response = maven::apply_if_none_match(
            maven::metadata_route_response(
                config,
                &maven_upstream,
                checker,
                &relative_path,
                checksum,
                now,
            )
            .await
            .unwrap_or_else(|error| maven::error_response(&error)),
            headers
                .get(header::IF_NONE_MATCH)
                .and_then(|value| value.to_str().ok()),
        );
        if method == "HEAD" {
            response.body.clear();
        }
        return response.into_http_response();
    }
    if let Some(relative_path) = maven_relative_path(path) {
        let route = match maven::parse_release_path(&relative_path) {
            Ok(route) => route,
            Err(error) => return maven::error_response(&error).into_http_response(),
        };
        let delivery_options = if method == "HEAD" {
            ArtifactDeliveryOptions::with_request_headers_for_head(&delivery, headers)
        } else {
            ArtifactDeliveryOptions::with_request_headers(&delivery, headers)
        };
        return maven::artifact_delivery_response(
            config,
            &maven_upstream,
            checker,
            &route,
            now,
            delivery_options,
        )
        .await
        .map(|response| response.into_http_response())
        .unwrap_or_else(|error| maven::error_response(&error).into_http_response());
    }

    if let Some(route) = parse_rubygems_route(path) {
        return match route {
            RubyGemsRoute::Versions => rubygems_upstream
                .fetch_versions_index(Some(headers))
                .await
                .unwrap_or_else(|error| rubygems::error_response(&error))
                .into_http_response(),
            RubyGemsRoute::Info { name } => rubygems::compact_info_response(
                config,
                &rubygems_upstream,
                &rubygems_upstream,
                checker,
                &name,
                now,
                headers,
            )
            .await
            .unwrap_or_else(|error| rubygems::error_response(&error))
            .into_http_response(),
            RubyGemsRoute::Artifact { filename } => rubygems::artifact_delivery_response(
                config,
                &rubygems_upstream,
                checker,
                &filename,
                now,
                ArtifactDeliveryOptions::with_request_headers(&delivery, headers),
            )
            .await
            .map(|response| response.into_http_response())
            .unwrap_or_else(|error| rubygems::error_response(&error).into_http_response()),
        };
    }

    if path.split('?').next().unwrap_or(path) == "/nuget/v3/index.json" {
        return nuget::service_index_response(config)
            .unwrap_or_else(|err| simple_response(502, &err.to_string()))
            .into_http_response();
    }
    if let Some((package, suffix)) = parse_nuget_registration_route(path) {
        return nuget::registration_resource_response(
            config,
            &nuget_upstream,
            checker,
            &package,
            &suffix,
            now,
        )
        .await
        .unwrap_or_else(nuget_error_response)
        .into_http_response();
    }
    if let Some(package) = parse_nuget_flat_index_route(path) {
        return nuget::flat_container_index_response(
            config,
            &nuget_upstream,
            checker,
            &package,
            now,
        )
        .await
        .unwrap_or_else(nuget_error_response)
        .into_http_response();
    }
    if let Some((package, version, filename)) = parse_nuget_flat_artifact_route(path) {
        let result = async {
            let artifact = nuget::lookup_artifact(&nuget_upstream, &package, &version).await?;
            let decision = crate::policy::PolicyEngine::new(config)
                .evaluate(&artifact, now, checker)
                .await;
            if !decision.allowed {
                return Ok::<_, crate::nuget::NugetError>(
                    RegistryResponse::json(
                        403,
                        &serde_json::to_value(&decision).unwrap_or_default(),
                    )
                    .unwrap_or_else(|_| simple_response(403, "policy denied"))
                    .into_http_response(),
                );
            }
            let mut upstream = artifact.upstream_url.ok_or_else(|| {
                crate::nuget::NugetError::InvalidMetadata(
                    "registration leaf has no packageContent".into(),
                )
            })?;
            if filename.ends_with(".nuspec") {
                upstream = upstream
                    .rsplit_once('/')
                    .map(|(base, _)| format!("{base}/{package}.nuspec"))
                    .unwrap_or(upstream);
            }
            Ok(delivery
                .deliver(
                    config,
                    crate::artifact::Ecosystem::Nuget,
                    upstream,
                    Some(headers),
                )
                .await
                .map_err(|err| crate::nuget::NugetError::InvalidMetadata(err.to_string()))?
                .into_http_response())
        }
        .await;
        return result.unwrap_or_else(|err| nuget_error_response(err).into_http_response());
    }

    if let Some((module, route)) = go::parse_route(path) {
        return go::route_response(
            config,
            &go_upstream,
            checker,
            &module,
            route,
            now,
            Some(ArtifactDeliveryOptions::with_request_headers(
                &delivery, headers,
            )),
        )
        .await
        .unwrap_or_else(|err| go_error_response(&err))
        .into_http_response();
    }

    match parse_cargo_route(path) {
        Some(CargoRoute::Config) => cargo::config_response(config).into_http_response(),
        Some(CargoRoute::Index { name }) => cargo::apply_if_none_match(
            cargo::index_response(config, &cargo_upstream, checker, &name, now)
                .await
                .unwrap_or_else(|err| cargo::error_response(&err)),
            headers
                .get(header::IF_NONE_MATCH)
                .and_then(|value| value.to_str().ok()),
        )
        .into_http_response(),
        Some(CargoRoute::Artifact { name, version }) => cargo::artifact_delivery_response(
            config,
            &cargo_upstream,
            checker,
            &name,
            &version,
            now,
            ArtifactDeliveryOptions::with_request_headers(&delivery, headers),
        )
        .await
        .map(|response| response.into_http_response())
        .unwrap_or_else(|err| cargo::error_response(&err).into_http_response()),
        None => match parse_npm_route(path) {
            Some(NpmRoute::Metadata { package }) => {
                npm::metadata_response(config, &npm_upstream, checker, &package, now)
                    .await
                    .unwrap_or_else(|err| npm::error_response(&err))
                    .into_http_response()
            }
            Some(NpmRoute::Artifact { package, tarball }) => npm::artifact_delivery_response(
                config,
                &npm_upstream,
                checker,
                npm::NpmArtifactRoute {
                    package: &package,
                    tarball: &tarball,
                },
                now,
                ArtifactDeliveryOptions::with_request_headers(&delivery, headers),
            )
            .await
            .map(|response| response.into_http_response())
            .unwrap_or_else(|err| npm::error_response(&err).into_http_response()),
            None => match parse_pypi_route(path) {
                Some(PypiRoute::SimpleRoot) => pypi::simple_root_response(config, &pypi_upstream)
                    .await
                    .unwrap_or_else(|err| pypi::error_response(&err))
                    .into_http_response(),
                Some(PypiRoute::SimpleProject { project }) => {
                    pypi::simple_project_response_for_accept(
                        config,
                        &pypi_upstream,
                        checker,
                        &project,
                        now,
                        accept,
                    )
                    .await
                    .unwrap_or_else(|err| pypi::error_response(&err))
                    .into_http_response()
                }
                Some(PypiRoute::Artifact {
                    project,
                    version,
                    filename,
                }) => pypi::artifact_delivery_response(
                    config,
                    &pypi_upstream,
                    checker,
                    pypi::PypiArtifactRoute {
                        project: &project,
                        version: &version,
                        filename: &filename,
                    },
                    now,
                    ArtifactDeliveryOptions::with_request_headers(&delivery, headers),
                )
                .await
                .map(|response| response.into_http_response())
                .unwrap_or_else(|err| pypi::error_response(&err).into_http_response()),
                None => simple_response(404, "not found").into_http_response(),
            },
        },
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum RubyGemsRoute {
    Versions,
    Info { name: String },
    Artifact { filename: String },
}

fn parse_maven_metadata_route(path: &str) -> Option<(String, Option<MetadataChecksum>)> {
    let path = path.split('?').next().unwrap_or(path);
    let relative = path.strip_prefix("/maven/")?;
    if relative.contains('%')
        || relative
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return None;
    }
    let (base, checksum) = if let Some((base, suffix)) = relative.rsplit_once('.') {
        if base.ends_with("maven-metadata.xml") {
            (base, Some(MetadataChecksum::from_suffix(suffix)?))
        } else {
            (relative, None)
        }
    } else {
        (relative, None)
    };
    if !base.ends_with("maven-metadata.xml") || base.split('/').count() < 2 {
        return None;
    }
    Some((base.to_string(), checksum))
}

fn maven_relative_path(path: &str) -> Option<String> {
    path.split('?')
        .next()
        .unwrap_or(path)
        .strip_prefix("/maven/")
        .map(str::to_string)
}

fn parse_rubygems_route(path: &str) -> Option<RubyGemsRoute> {
    let path = path.split('?').next().unwrap_or(path);
    if path == "/rubygems/versions" {
        return Some(RubyGemsRoute::Versions);
    }
    if let Some(name) = path.strip_prefix("/rubygems/info/") {
        let name = percent_decode_segment(name)?;
        if !name.contains('/') && rubygems::validate_name(&name).is_ok() {
            return Some(RubyGemsRoute::Info { name });
        }
        return None;
    }
    if let Some(filename) = path.strip_prefix("/rubygems/gems/") {
        let filename = percent_decode_segment(filename)?;
        if !filename.is_empty() && !filename.contains('/') && filename.ends_with(".gem") {
            return Some(RubyGemsRoute::Artifact { filename });
        }
    }
    None
}

fn parse_nuget_registration_route(path: &str) -> Option<(String, String)> {
    let rest = path
        .split('?')
        .next()
        .unwrap_or(path)
        .strip_prefix("/nuget/v3/registration-semver2/")?;
    let mut segments = rest.split('/');
    let package = segments.next()?;
    let suffix = segments.collect::<Vec<_>>().join("/");
    (!package.is_empty() && !suffix.is_empty() && suffix.ends_with(".json"))
        .then(|| (crate::artifact::normalize_nuget_name(package), suffix))
}
fn parse_nuget_flat_artifact_route(path: &str) -> Option<(String, String, String)> {
    let segments = path
        .split('?')
        .next()
        .unwrap_or(path)
        .strip_prefix("/nuget/v3/flatcontainer/")?
        .split('/')
        .collect::<Vec<_>>();
    match segments.as_slice() {
        [package, version, filename]
            if !package.is_empty()
                && !version.is_empty()
                && crate::artifact::normalize_nuget_version(version)
                    .ok()
                    .is_some_and(|normalized| {
                        *filename
                            == format!(
                                "{}.{}.nupkg",
                                crate::artifact::normalize_nuget_name(package),
                                normalized
                            )
                            || *filename
                                == format!(
                                    "{}.nuspec",
                                    crate::artifact::normalize_nuget_name(package)
                                )
                    }) =>
        {
            Some((
                crate::artifact::normalize_nuget_name(package),
                crate::artifact::normalize_nuget_version(version).ok()?,
                (*filename).to_string(),
            ))
        }
        _ => None,
    }
}
fn parse_nuget_flat_index_route(path: &str) -> Option<String> {
    let package = path
        .split('?')
        .next()
        .unwrap_or(path)
        .strip_prefix("/nuget/v3/flatcontainer/")?
        .strip_suffix("/index.json")?;
    (!package.is_empty() && !package.contains('/'))
        .then(|| crate::artifact::normalize_nuget_name(package))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CargoRoute {
    Config,
    Index { name: String },
    Artifact { name: String, version: String },
}

fn parse_cargo_route(path: &str) -> Option<CargoRoute> {
    let path = path.split('?').next().unwrap_or(path);
    if path == "/cargo/config.json" {
        return Some(CargoRoute::Config);
    }
    if let Some(rest) = path.strip_prefix("/cargo/api/v1/crates/") {
        let parts = rest.split('/').collect::<Vec<_>>();
        if let [name, version, "download"] = parts.as_slice() {
            cargo::sparse_path(name).ok()?;
            return Some(CargoRoute::Artifact {
                name: name.to_ascii_lowercase(),
                version: (*version).to_string(),
            });
        }
        return None;
    }
    let rest = path.strip_prefix("/cargo/")?;
    Some(CargoRoute::Index {
        name: cargo::name_from_sparse_path(rest).ok()?,
    })
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
    use crate::config::{
        AllowlistEntry, ArtifactBehavior, BlocklistEntry, LocalOsvConfig, MissingPublishTime,
        OsvErrorBehavior, OsvSource,
    };
    use crate::malicious::{
        MaliciousError, MaliciousHit, OsvDumpClient, OsvHttpClient, SqliteMaliciousChecker,
    };
    use crate::npm::NpmError;
    use crate::policy::PolicyEngine;
    use crate::pypi::{SimpleFile, SimpleProject};
    use axum::http::StatusCode;
    use chrono::Duration as ChronoDuration;
    use rusqlite::{Connection, params};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::io::{Cursor, Write};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;
    use tower::ServiceExt;
    use zip::{ZipWriter, write::SimpleFileOptions};

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
        osv_id: String,
        severity: Option<f64>,
    }

    impl MaliciousPackageChecker {
        fn new(package: &str) -> Self {
            Self {
                package: package.to_string(),
                osv_id: "MAL-2026-000001".to_string(),
                severity: None,
            }
        }

        fn vulnerable(package: &str) -> Self {
            Self {
                package: package.to_string(),
                osv_id: "GHSA-e2e-vulnerable".to_string(),
                severity: Some(9.8),
            }
        }
    }

    #[async_trait]
    impl MaliciousChecker for MaliciousPackageChecker {
        async fn check(&self, artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            if artifact.identity() == self.package {
                Ok(vec![MaliciousHit {
                    osv_id: self.osv_id.clone(),
                    summary: Some("OSV fixture".to_string()),
                    source: "osv".to_string(),
                    modified: None,
                    effective_severity: self.severity.map(|base_score| {
                        crate::malicious::OsvEffectiveSeverity {
                            severity_type: "CVSS_V3".to_string(),
                            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                            base_score,
                        }
                    }),
                    evaluation_error: None,
                }])
            } else {
                Ok(Vec::new())
            }
        }
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
        async fn fetch_bytes(&self, url: &str) -> Result<Vec<u8>, MaliciousError> {
            if url.ends_with("/modified_id.csv") && !self.responses.contains_key(url) {
                return Ok(Vec::new());
            }
            self.responses
                .get(url)
                .cloned()
                .ok_or_else(|| MaliciousError::Sync(format!("missing fixture response for {url}")))
        }

        async fn fetch_archive(&self, url: &str) -> Result<std::fs::File, MaliciousError> {
            crate::malicious::fixture_archive_file(&self.fetch_bytes(url).await?)
        }
    }

    const OSV_DUMP_BASE_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities";

    fn all_zip_url(ecosystem: &str) -> String {
        format!("{OSV_DUMP_BASE_URL}/{ecosystem}/all.zip")
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

    fn advisory_json(id: &str, ecosystem: &str, name: &str, version: &str) -> Vec<u8> {
        format!(
            r#"{{
                "schema_version": "1.7.3",
                "id": "{id}",
                "published": "2026-07-01T00:00:00Z",
                "modified": "2026-07-02T00:00:00Z",
                "summary": "Malicious code in {name}",
                "affected": [{{
                    "package": {{ "name": "{name}", "ecosystem": "{ecosystem}" }},
                    "versions": ["{version}"],
                    "ranges": []
                }}]
            }}"#
        )
        .into_bytes()
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
        Utc::now() - ChronoDuration::hours(12)
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

    #[test]
    fn parses_only_owned_rubygems_read_routes() {
        assert_eq!(
            parse_rubygems_route("/rubygems/versions"),
            Some(RubyGemsRoute::Versions)
        );
        assert_eq!(
            parse_rubygems_route("/rubygems/info/demo%2Dgem"),
            Some(RubyGemsRoute::Info {
                name: "demo-gem".into()
            })
        );
        assert_eq!(
            parse_rubygems_route("/rubygems/gems/demo-1.0.0.gem"),
            Some(RubyGemsRoute::Artifact {
                filename: "demo-1.0.0.gem".into()
            })
        );
        assert_eq!(parse_rubygems_route("/rubygems/api/v1/gems"), None);
        assert_eq!(parse_rubygems_route("/rubygems/info/../secret"), None);
    }

    #[test]
    fn parses_only_strict_maven_metadata_routes() {
        assert_eq!(
            parse_maven_metadata_route("/maven/com/acme/demo/maven-metadata.xml"),
            Some(("com/acme/demo/maven-metadata.xml".to_string(), None))
        );
        assert_eq!(
            parse_maven_metadata_route("/maven/com/acme/demo/maven-metadata.xml.sha256"),
            Some((
                "com/acme/demo/maven-metadata.xml".to_string(),
                Some(MetadataChecksum::Sha256)
            ))
        );
        assert_eq!(
            parse_maven_metadata_route("/maven/org/plugins/maven-metadata.xml.sha1?x=1"),
            Some((
                "org/plugins/maven-metadata.xml".to_string(),
                Some(MetadataChecksum::Sha1)
            ))
        );
        assert_eq!(
            parse_maven_metadata_route("/maven/com/acme/demo/1.0/demo-1.0.jar"),
            None
        );
        assert_eq!(
            parse_maven_metadata_route("/maven/com/acme/../secret/maven-metadata.xml"),
            None
        );
        assert_eq!(
            parse_maven_metadata_route("/maven/com/acme%2Fdemo/maven-metadata.xml"),
            None
        );
        assert_eq!(
            parse_maven_metadata_route("/maven/com/acme/demo/maven-metadata.xml.sha3"),
            None
        );
    }

    #[tokio::test]
    async fn e2e_maven_route_redirects_allowed_and_blocks_direct_bytes() {
        let (upstream, requests, server) = serve_maven_upstream().await;
        let mut config = Config::default();
        config.upstreams.maven.repository_url = upstream;
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
        let path = "/maven/com/acme/demo/1.0/demo-1.0.jar";

        let allowed = route_http_request_with_accept_and_headers(
            &config,
            &CleanChecker,
            "GET",
            path,
            None,
            &HeaderMap::new(),
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::FOUND);
        assert!(
            allowed
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|location| location.ends_with("/com/acme/demo/1.0/demo-1.0.jar"))
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        let observed = requests.lock().unwrap().clone();
        assert!(
            observed
                .iter()
                .any(|request| request.starts_with("head /com/acme/demo/1.0/demo-1.0.pom "))
        );
        assert!(
            observed
                .iter()
                .any(|request| request.starts_with("head /com/acme/demo/1.0/demo-1.0.jar "))
        );

        let before_block = observed.len();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Maven,
            name: "com.acme:demo".to_string(),
            versions: vec!["1.0".to_string()],
            reason: "blocked fixture".to_string(),
        });
        let blocked = route_http_request_with_accept_and_headers(
            &config,
            &CleanChecker,
            "GET",
            path,
            None,
            &HeaderMap::new(),
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(blocked.into_body(), usize::MAX)
            .await
            .unwrap();
        let decision: crate::policy::Decision = serde_json::from_slice(&body).unwrap();
        assert_eq!(decision.package, "maven:com.acme:demo@1.0");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let after_block = requests.lock().unwrap().clone();
        assert_eq!(after_block.len(), before_block + 1);
        assert!(
            after_block
                .last()
                .unwrap()
                .starts_with("head /com/acme/demo/1.0/demo-1.0.pom ")
        );

        let before_blocked_pom = after_block.len();
        let blocked_pom = route_http_request_with_accept_and_headers(
            &config,
            &CleanChecker,
            "GET",
            "/maven/com/acme/demo/1.0/demo-1.0.pom",
            None,
            &HeaderMap::new(),
        )
        .await;
        assert_eq!(blocked_pom.status(), StatusCode::FORBIDDEN);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let after_blocked_pom = requests.lock().unwrap().clone();
        assert_eq!(after_blocked_pom.len(), before_blocked_pom + 1);
        assert!(
            after_blocked_pom
                .last()
                .unwrap()
                .starts_with("head /com/acme/demo/1.0/demo-1.0.pom ")
        );
        assert_eq!(
            after_blocked_pom
                .iter()
                .filter(|request| request.starts_with("get /com/acme/demo/1.0/demo-1.0.pom "))
                .count(),
            0
        );
        server.abort();
    }

    #[tokio::test]
    async fn e2e_maven_proxy_route_preserves_artifact_bytes() {
        let (upstream, requests, server) = serve_maven_upstream().await;
        let mut config = Config::default();
        config.upstreams.maven.repository_url = upstream;
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
        let response = route_http_request_with_accept_and_headers(
            &config,
            &CleanChecker,
            "GET",
            "/maven/com/acme/demo/1.0/demo-1.0.jar",
            None,
            &HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"bytes");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let observed = requests.lock().unwrap().clone();
        assert_eq!(
            observed
                .iter()
                .filter(|request| request.starts_with("get /com/acme/demo/1.0/demo-1.0.jar "))
                .count(),
            1
        );

        let head = route_http_request_with_accept_and_headers(
            &config,
            &CleanChecker,
            "HEAD",
            "/maven/com/acme/demo/1.0/demo-1.0.jar",
            None,
            &HeaderMap::new(),
        )
        .await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
        let head_body = axum::body::to_bytes(head.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(head_body.is_empty());
        tokio::time::sleep(Duration::from_millis(20)).await;
        let observed = requests.lock().unwrap().clone();
        assert_eq!(
            observed
                .iter()
                .filter(|request| request.starts_with("head /com/acme/demo/1.0/demo-1.0.jar "))
                .count(),
            1
        );
        server.abort();
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
        assert!(
            metadata["versions"]
                .as_object()
                .unwrap()
                .contains_key("1.0.0")
        );
        assert!(
            !metadata["versions"]
                .as_object()
                .unwrap()
                .contains_key("1.0.1")
        );
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
        assert!(
            metadata["versions"]
                .as_object()
                .unwrap()
                .contains_key("1.0.0")
        );
        assert!(
            !metadata["versions"]
                .as_object()
                .unwrap()
                .contains_key("1.0.1")
        );
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
        assert!(
            !simple_body
                .to_string()
                .contains("demo-2.0.0-py3-none-any.whl")
        );

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
    async fn direct_npm_and_pypi_artifacts_block_vulnerabilities_before_delivery() {
        let config = Config::default();
        let npm_upstream = StaticUpstream::with("demo", npm_demo_metadata());
        let pypi_upstream = StaticPypiUpstream::with("Demo", pypi_simple_fixture());

        let npm = route_request_with_upstreams(
            &config,
            "GET",
            "/npm/demo/-/demo-1.0.1.tgz",
            now(),
            &MaliciousPackageChecker::vulnerable("npm:demo@1.0.1"),
            &npm_upstream,
            &pypi_upstream,
        )
        .await;
        let pypi = route_request_with_upstreams(
            &config,
            "GET",
            "/pypi/packages/demo/1.0.1/demo-1.0.1.tar.gz",
            now(),
            &MaliciousPackageChecker::vulnerable("pypi:demo@1.0.1"),
            &npm_upstream,
            &pypi_upstream,
        )
        .await;

        for response in [npm, pypi] {
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(response.status, 403);
            assert_eq!(body["reason"], "vulnerable");
            assert_eq!(body["rule_id"], "GHSA-e2e-vulnerable");
        }
    }

    #[tokio::test]
    async fn background_malicious_sync_runs_immediately_for_local_config() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("malicious.sqlite");
        let npm_advisory = advisory_json("MAL-2026-000001", "npm", "demo", "1.0.1");
        let client = FixtureDumpClient::new([
            (
                all_zip_url("npm"),
                zip_bytes([("MAL-2026-000001.json", npm_advisory.as_slice())]),
            ),
            (all_zip_url("PyPI"), zip_bytes([])),
        ]);
        let local_config = LocalOsvConfig {
            sqlite_path: db.clone(),
            background_sync: true,
            sync_interval: Duration::from_secs(60 * 60),
            ..LocalOsvConfig::default()
        };

        let _task = spawn_background_osv_sync(local_config.clone(), Arc::new(client));

        wait_for_sync_status(&db, "PyPI", "healthy").await;
        let checker = SqliteMaliciousChecker::new(&local_config);
        let hits = checker
            .check(&Artifact::package(Ecosystem::Npm, "demo", "1.0.1", None))
            .await
            .unwrap();
        assert_eq!(hits[0].osv_id, "MAL-2026-000001");
    }

    #[tokio::test]
    async fn background_malicious_sync_records_failed_first_sync() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("malicious.sqlite");
        let client = FixtureDumpClient::new([]);
        let local_config = LocalOsvConfig {
            sqlite_path: db.clone(),
            background_sync: true,
            sync_interval: Duration::from_secs(60 * 60),
            ..LocalOsvConfig::default()
        };

        let _task = spawn_background_osv_sync(local_config, Arc::new(client));

        wait_for_sync_status(&db, "npm", "failed").await;
        let connection = Connection::open(&db).unwrap();
        let error_summary: String = connection
            .query_row(
                "SELECT error_summary FROM sync_state WHERE ecosystem = 'npm'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(error_summary.contains("missing fixture response"));
    }

    #[test]
    fn background_retry_delay_is_bounded_and_below_normal_interval() {
        let interval = Duration::from_secs(60 * 60);
        assert_eq!(
            background_retry_delay(interval, 1, BACKGROUND_RETRY_POLICY),
            Duration::from_secs(5)
        );
        assert_eq!(
            background_retry_delay(interval, 2, BACKGROUND_RETRY_POLICY),
            Duration::from_secs(10)
        );
        assert_eq!(
            background_retry_delay(interval, 3, BACKGROUND_RETRY_POLICY),
            Duration::from_secs(20)
        );
        assert_eq!(
            background_retry_delay(interval, 20, BACKGROUND_RETRY_POLICY),
            BACKGROUND_RETRY_POLICY.maximum
        );
        assert!(background_retry_delay(interval, 20, BACKGROUND_RETRY_POLICY) < interval);
        assert_eq!(
            background_retry_delay(Duration::from_secs(8), 20, BACKGROUND_RETRY_POLICY),
            Duration::from_secs(4)
        );
    }

    #[tokio::test]
    async fn background_retry_targets_only_failed_ecosystems() {
        struct RetryClient {
            archives: Mutex<BTreeMap<String, usize>>,
        }

        #[async_trait]
        impl OsvDumpClient for RetryClient {
            async fn fetch_bytes(&self, _url: &str) -> Result<Vec<u8>, MaliciousError> {
                Ok(Vec::new())
            }

            async fn fetch_archive(&self, url: &str) -> Result<std::fs::File, MaliciousError> {
                let attempt = {
                    let mut archives = self.archives.lock().unwrap();
                    let attempt = archives.entry(url.to_string()).or_default();
                    *attempt += 1;
                    *attempt
                };
                if url.ends_with("/npm/all.zip") && attempt == 1 {
                    return Err(MaliciousError::Sync("transient npm failure".to_string()));
                }
                crate::malicious::fixture_archive_file(&zip_bytes([]))
            }
        }

        let dir = tempdir().unwrap();
        let local_config = LocalOsvConfig {
            sqlite_path: dir.path().join("malicious.sqlite"),
            background_sync: true,
            sync_interval: Duration::from_secs(1),
            ..LocalOsvConfig::default()
        };
        let client = Arc::new(RetryClient {
            archives: Mutex::new(BTreeMap::new()),
        });
        let task = spawn_background_osv_sync_with_policy(
            local_config,
            Arc::clone(&client) as Arc<dyn OsvDumpClient>,
            BackgroundRetryPolicy {
                initial: Duration::from_millis(10),
                maximum: Duration::from_millis(20),
            },
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let attempts = client.archives.lock().unwrap().values().sum::<usize>();
                if attempts > ALL_OSV_ECOSYSTEMS.len() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();

        let archives = client.archives.lock().unwrap();
        assert_eq!(archives[&all_zip_url("npm")], 2);
        for ecosystem in ["PyPI", "Go", "crates.io", "NuGet", "RubyGems", "Maven"] {
            assert_eq!(archives[&all_zip_url(ecosystem)], 1, "{ecosystem}");
        }
        drop(archives);
        drop(task);
    }

    #[tokio::test]
    async fn local_mode_filters_npm_metadata_and_blocks_artifact_without_osv_http() {
        let dir = tempdir().unwrap();
        let mut config = local_malicious_config(dir.path().join("malicious.sqlite"));
        insert_local_malicious_version(&config, Ecosystem::Npm, "demo", "1.0.1", "MAL-2026-000001");
        let metadata_body = npm_demo_metadata().to_string();
        let (registry_url, metadata_request) = serve_http_once(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            metadata_body.len(),
            metadata_body
        ))
        .await;
        config.upstreams.npm.registry_url = registry_url;

        let response = route_request(&config, "GET", "/npm/demo").await;

        let metadata: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response.status, 200);
        assert!(
            metadata["versions"]
                .as_object()
                .unwrap()
                .contains_key("1.0.0")
        );
        assert!(
            !metadata["versions"]
                .as_object()
                .unwrap()
                .contains_key("1.0.1")
        );
        assert!(metadata_request.await.unwrap().starts_with("get /demo "));

        let artifact_body = npm_demo_metadata().to_string();
        let (registry_url, artifact_request) = serve_http_once(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            artifact_body.len(),
            artifact_body
        ))
        .await;
        config.upstreams.npm.registry_url = registry_url;
        let blocked = route_request(&config, "GET", "/npm/demo/-/demo-1.0.1.tgz").await;
        let blocked_body: Value = serde_json::from_slice(&blocked.body).unwrap();

        assert_eq!(blocked.status, 403);
        assert_eq!(blocked_body["reason"], "malicious");
        assert_eq!(blocked_body["rule_id"], "MAL-2026-000001");
        assert!(artifact_request.await.unwrap().starts_with("get /demo "));
    }

    #[tokio::test]
    async fn local_request_path_reads_sqlite_while_write_transaction_is_active() {
        let dir = tempdir().unwrap();
        let mut config = local_malicious_config(dir.path().join("malicious.sqlite"));
        insert_local_malicious_version(&config, Ecosystem::Npm, "demo", "1.0.1", "MAL-2026-000001");
        let mut writer = Connection::open(&config.policy.osv.local.sqlite_path).unwrap();
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
        let metadata_body = npm_demo_metadata().to_string();
        let (registry_url, metadata_request) = serve_http_once(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            metadata_body.len(),
            metadata_body
        ))
        .await;
        config.upstreams.npm.registry_url = registry_url;

        let response = tokio::time::timeout(
            Duration::from_secs(2),
            route_request(&config, "GET", "/npm/demo"),
        )
        .await
        .unwrap();

        let metadata: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response.status, 200);
        assert!(
            metadata["versions"]
                .as_object()
                .unwrap()
                .contains_key("1.0.0")
        );
        assert!(
            !metadata["versions"]
                .as_object()
                .unwrap()
                .contains_key("1.0.1")
        );
        assert!(metadata_request.await.unwrap().starts_with("get /demo "));
        drop(transaction);
    }

    #[tokio::test]
    async fn local_mode_filters_pypi_metadata_and_blocks_artifact_without_osv_http() {
        let dir = tempdir().unwrap();
        let mut config = local_malicious_config(dir.path().join("malicious.sqlite"));
        // This route uses wall-clock policy evaluation; retain a deliberate
        // age gap between the fixed fixture's old and new uploads.
        config.policy.minimum_age = Duration::from_secs(120 * 60 * 60);
        insert_local_malicious_version(
            &config,
            Ecosystem::Pypi,
            "Demo",
            "1.0.1",
            "MAL-2026-000002",
        );
        let simple_body = serde_json::to_string(&pypi_simple_fixture()).unwrap();
        let (simple_url, simple_request) = serve_http_once(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/vnd.pypi.simple.v1+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            simple_body.len(),
            simple_body
        ))
        .await;
        config.upstreams.pypi.simple_url = simple_url;

        let response = route_request_with_accept(
            &config,
            "GET",
            "/pypi/simple/Demo/",
            Some("application/vnd.pypi.simple.v1+json"),
        )
        .await;

        let simple: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(simple["versions"], json!(["1.0.0"]));
        assert!(!simple.to_string().contains("demo-1.0.1.tar.gz"));
        assert!(simple_request.await.unwrap().starts_with("get /demo/ "));

        let artifact_body = serde_json::to_string(&pypi_simple_fixture()).unwrap();
        let (simple_url, artifact_request) = serve_http_once(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/vnd.pypi.simple.v1+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            artifact_body.len(),
            artifact_body
        ))
        .await;
        config.upstreams.pypi.simple_url = simple_url;
        let blocked = route_request(
            &config,
            "GET",
            "/pypi/packages/demo/1.0.1/demo-1.0.1.tar.gz",
        )
        .await;
        let blocked_body: Value = serde_json::from_slice(&blocked.body).unwrap();

        assert_eq!(blocked.status, 403);
        assert_eq!(blocked_body["reason"], "malicious");
        assert_eq!(blocked_body["rule_id"], "MAL-2026-000002");
        assert!(artifact_request.await.unwrap().starts_with("get /demo/ "));
    }

    #[tokio::test]
    async fn local_mode_allowlist_bypass_osv_skips_sqlite_malicious_check() {
        let dir = tempdir().unwrap();
        let mut config = local_malicious_config(dir.path().join("malicious.sqlite"));
        insert_local_malicious_version(&config, Ecosystem::Npm, "demo", "1.0.1", "MAL-2026-000003");
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::Npm,
            name: "demo".to_string(),
            version: "1.0.1".to_string(),
            bypass_age_gate: false,
            bypass_osv: true,
            reason: "trusted local exception".to_string(),
        });
        let metadata_body = npm_demo_metadata().to_string();
        let (registry_url, _) = serve_http_once(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            metadata_body.len(),
            metadata_body
        ))
        .await;
        config.upstreams.npm.registry_url = registry_url;

        let response = router(config)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/npm/demo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let metadata: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            metadata["versions"]
                .as_object()
                .unwrap()
                .contains_key("1.0.1")
        );
    }

    #[tokio::test]
    async fn router_rejects_saturated_ingress_without_contacting_upstream() {
        let (registry_url, accepted, release) = blocking_npm_upstream().await;
        let mut config = Config::default();
        config.upstreams.npm.registry_url = registry_url;
        config.limits.ingress_requests = 1;
        config.limits.egress_requests = 2;
        let app = router(config);

        let active = tokio::spawn(app.clone().oneshot(registry_request()));
        tokio::time::timeout(Duration::from_secs(1), accepted.notified())
            .await
            .unwrap();
        let overloaded = app.clone().oneshot(registry_request()).await.unwrap();
        assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(overloaded.headers()["retry-after"], "1");

        release.notify_one();
        assert_eq!(active.await.unwrap().unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_times_out_saturated_egress_independently_of_ingress() {
        let (registry_url, accepted, release) = blocking_npm_upstream().await;
        let mut config = Config::default();
        config.upstreams.npm.registry_url = registry_url;
        config.limits.ingress_requests = 2;
        config.limits.egress_requests = 1;
        config.limits.queue_timeout = Duration::from_millis(20);
        let app = router(config);

        let active = tokio::spawn(app.clone().oneshot(registry_request()));
        tokio::time::timeout(Duration::from_secs(1), accepted.notified())
            .await
            .unwrap();
        let overloaded = app.clone().oneshot(registry_request()).await.unwrap();
        assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(overloaded.headers()["retry-after"], "1");
        let body = axum::body::to_bytes(overloaded.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("upstream concurrency"));

        let artifact_overload = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/npm/demo/-/demo-1.0.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(artifact_overload.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(artifact_overload.headers()["retry-after"], "1");

        release.notify_one();
        assert_eq!(active.await.unwrap().unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn live_osv_overload_is_tracked_even_when_policy_is_fail_open() {
        let mut config = Config::default();
        config.policy.osv.on_error = OsvErrorBehavior::Allow;
        config.limits.egress_requests = 1;
        config.limits.queue_timeout = Duration::from_millis(10);
        let budgets = Arc::new(RuntimeBudgets::new(&config.limits));
        let _held = budgets.install_egress().await.unwrap();
        let checker = OsvHttpClient::with_vulnerability_policy_and_budgets(
            "http://127.0.0.1:9",
            true,
            Arc::clone(&budgets),
        );
        let artifact = Artifact::package(
            Ecosystem::Npm,
            "demo",
            "1.0.0",
            Some(Utc::now() - ChronoDuration::days(10)),
        );

        let (decision, overloaded) = track_request_overload(PolicyEngine::new(&config).evaluate(
            &artifact,
            Utc::now(),
            &checker,
        ))
        .await;

        assert!(decision.allowed, "fixture must exercise fail-open handling");
        assert!(overloaded, "HTTP boundary must override fail-open overload");
    }

    fn registry_request() -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("GET")
            .uri("/npm/demo")
            .body(Body::empty())
            .unwrap()
    }

    async fn blocking_npm_upstream() -> (String, Arc<Notify>, Arc<Notify>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let task_accepted = Arc::clone(&accepted);
        let task_release = Arc::clone(&release);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            stream.read(&mut request).await.unwrap();
            task_accepted.notify_one();
            task_release.notified().await;
            let body = json!({"name":"demo","versions":{},"dist-tags":{},"time":{}}).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (format!("http://{address}"), accepted, release)
    }

    #[tokio::test]
    async fn app_state_reuses_upstream_connection_across_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(Notify::new());
        let body = json!({"name":"demo","versions":{},"dist-tags":{},"time":{}}).to_string();
        let server = {
            let accepted = Arc::clone(&accepted);
            let requests = Arc::clone(&requests);
            let completed = Arc::clone(&completed);
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    accepted.fetch_add(1, AtomicOrdering::SeqCst);
                    let body = body.clone();
                    let requests = Arc::clone(&requests);
                    let completed = Arc::clone(&completed);
                    tokio::spawn(async move {
                        loop {
                            let mut buffer = [0_u8; 4096];
                            let Ok(bytes) = stream.read(&mut buffer).await else {
                                return;
                            };
                            if bytes == 0 {
                                return;
                            }
                            let response = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: keep-alive\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            if stream.write_all(response.as_bytes()).await.is_err() {
                                return;
                            }
                            if requests.fetch_add(1, AtomicOrdering::SeqCst) + 1 == 2 {
                                completed.notify_one();
                            }
                        }
                    });
                }
            })
        };
        let mut config = Config::default();
        config.upstreams.npm.registry_url = format!("http://{address}");
        let app = router(config);

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("GET")
                        .uri("/npm/demo")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), completed.notified())
            .await
            .unwrap();

        assert_eq!(requests.load(AtomicOrdering::SeqCst), 2);
        assert_eq!(accepted.load(AtomicOrdering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn nuget_metadata_and_artifact_share_the_state_client_pool() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(Notify::new());
        let server = {
            let accepted = Arc::clone(&accepted);
            let requests = Arc::clone(&requests);
            let completed = Arc::clone(&completed);
            let origin = origin.clone();
            tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    accepted.fetch_add(1, AtomicOrdering::SeqCst);
                    let origin = origin.clone();
                    let requests = Arc::clone(&requests);
                    let completed = Arc::clone(&completed);
                    tokio::spawn(async move {
                        loop {
                            let mut buffer = [0_u8; 4096];
                            let Ok(bytes) = stream.read(&mut buffer).await else {
                                return;
                            };
                            if bytes == 0 {
                                return;
                            }
                            let request = String::from_utf8_lossy(&buffer[..bytes]);
                            let path = request
                                .lines()
                                .next()
                                .and_then(|line| line.split_whitespace().nth(1))
                                .unwrap_or_default();
                            let (content_type, body) = match path {
                                "/v3/index.json" => (
                                    "application/json",
                                    json!({"resources":[{
                                        "@type":"RegistrationsBaseUrl/3.6.0",
                                        "@id":format!("{origin}/registration")
                                    }]})
                                    .to_string(),
                                ),
                                "/registration/demo/index.json" => (
                                    "application/json",
                                    json!({"items":[{"items":[{
                                        "catalogEntry":{
                                            "version":"1.0.0",
                                            "published":"2020-01-01T00:00:00Z"
                                        },
                                        "packageContent":format!("{origin}/packages/demo.1.0.0.nupkg")
                                    }]}]})
                                    .to_string(),
                                ),
                                "/packages/demo.1.0.0.nupkg" => {
                                    ("application/octet-stream", "nupkg".to_string())
                                }
                                _ => return,
                            };
                            let response = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: keep-alive\r\n\r\n{body}",
                                body.len()
                            );
                            if stream.write_all(response.as_bytes()).await.is_err() {
                                return;
                            }
                            if requests.fetch_add(1, AtomicOrdering::SeqCst) + 1 == 3 {
                                completed.notify_one();
                            }
                        }
                    });
                }
            })
        };
        let mut config = Config::default();
        config.upstreams.nuget.service_index_url = format!("{origin}/v3/index.json");
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        config.policy.minimum_age = Duration::ZERO;
        config.policy.missing_publish_time = MissingPublishTime::Allow;
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;

        let response = router(config)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/nuget/v3/flatcontainer/demo/1.0.0/demo.1.0.0.nupkg")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
            "nupkg"
        );
        tokio::time::timeout(Duration::from_secs(1), completed.notified())
            .await
            .unwrap();

        assert_eq!(requests.load(AtomicOrdering::SeqCst), 3);
        assert_eq!(accepted.load(AtomicOrdering::SeqCst), 1);
        server.abort();
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
    async fn router_streams_npm_artifact_proxy_response() {
        let (artifact_base_url, artifact_request) = serve_http_once(
            "HTTP/1.1 200 OK\r\n\
             content-type: application/octet-stream\r\n\
             content-length: 15\r\n\
             etag: \"router-npm\"\r\n\
             connection: close\r\n\
             \r\n\
             router-artifact"
                .to_string(),
        )
        .await;
        let artifact_url = format!("{artifact_base_url}/demo/-/demo-1.0.0.tgz");
        let metadata_body = json!({
            "name": "demo",
            "time": { "1.0.0": "2026-06-01T00:00:00Z" },
            "versions": {
                "1.0.0": {
                    "name": "demo",
                    "version": "1.0.0",
                    "dist": { "tarball": artifact_url }
                }
            }
        })
        .to_string();
        let (registry_url, metadata_request) = serve_http_once(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            metadata_body.len(),
            metadata_body
        ))
        .await;
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        config.upstreams.npm.registry_url = registry_url;
        config.artifacts.trusted_origins.push(
            reqwest::Url::parse(&artifact_base_url)
                .unwrap()
                .origin()
                .ascii_serialization(),
        );

        let response = router(config)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/npm/demo/-/demo-1.0.0.tgz")
                    .header(header::RANGE, "bytes=0-14")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream")
        );
        assert_eq!(
            response
                .headers()
                .get(header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some("\"router-npm\"")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let metadata_request = metadata_request.await.unwrap();
        let artifact_request = artifact_request.await.unwrap();

        assert_eq!(&body[..], b"router-artifact");
        assert!(metadata_request.starts_with("get /demo "));
        assert!(artifact_request.contains("range: bytes=0-14"));
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

    async fn serve_http_once(response: String) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4096];
            let bytes = stream.read(&mut buffer).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buffer[..bytes]).to_ascii_lowercase()
        });
        (format!("http://{address}"), handle)
    }

    async fn serve_maven_upstream() -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>)
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let captured = Arc::clone(&captured);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 8192];
                    let bytes = stream.read(&mut buffer).await.unwrap();
                    let request = String::from_utf8_lossy(&buffer[..bytes]).to_ascii_lowercase();
                    captured.lock().unwrap().push(request.clone());
                    let (content_type, body) = if request
                        .starts_with("get /com/acme/demo/1.0/demo-1.0.pom ")
                    {
                        (
                            "application/xml",
                            "<project><groupId>com.acme</groupId><artifactId>demo</artifactId><version>1.0</version></project>",
                        )
                    } else {
                        ("application/java-archive", "bytes")
                    };
                    let include_body = !request.starts_with("head ");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nlast-modified: Sun, 01 Jun 2025 00:00:00 GMT\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        if include_body { body } else { "" }
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        (format!("http://{address}"), requests, handle)
    }

    async fn wait_for_sync_status(db: &std::path::Path, ecosystem: &str, expected_status: &str) {
        for _ in 0..50 {
            let status = Connection::open(db).ok().and_then(|connection| {
                connection
                    .query_row(
                        "SELECT status FROM sync_state WHERE ecosystem = ?1",
                        [ecosystem],
                        |row| row.get::<_, String>(0),
                    )
                    .ok()
            });
            if status.as_deref() == Some(expected_status) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {ecosystem} sync status {expected_status}");
    }

    fn npm_demo_metadata() -> Value {
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
        })
    }

    fn local_malicious_config(sqlite_path: std::path::PathBuf) -> Config {
        let mut config = Config::default();
        config.policy.osv.source = OsvSource::Local;
        config.policy.osv.api_url = "http://127.0.0.1:9".to_string();
        config.policy.osv.local.sqlite_path = sqlite_path;
        config
    }

    fn insert_local_malicious_version(
        config: &Config,
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        osv_id: &str,
    ) {
        SqliteMaliciousChecker::initialize(&config.policy.osv.local.sqlite_path).unwrap();
        let connection = Connection::open(&config.policy.osv.local.sqlite_path).unwrap();
        let ecosystem_name = ecosystem.osv_name();
        let now = Utc::now().to_rfc3339();
        connection
            .execute(
                r#"
INSERT INTO dataset_generations (
    ecosystem, dataset_version, status, staged_at, activated_at, high_watermark
) VALUES (?1, 1, 'active', ?2, ?2, NULL)
"#,
                params![ecosystem_name, now],
            )
            .unwrap();
        let generation_id = connection.last_insert_rowid();
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
    error_summary,
    active_generation_id
) VALUES (?1, 'test', NULL, ?2, ?2, 'healthy', NULL, ?3)
"#,
                params![ecosystem_name, now, generation_id],
            )
            .unwrap();
        connection
            .execute(
                r#"
INSERT INTO osv_advisories (
    generation_id,
    osv_id,
    summary,
    modified,
    published,
    withdrawn,
    raw_json,
    source,
    imported_at
) VALUES (?1, ?2, 'local malicious fixture', ?3, NULL, NULL, '{}', 'test', ?3)
"#,
                params![generation_id, osv_id, now],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO osv_affected_packages (generation_id, osv_id, ecosystem, name, affected_order) VALUES (?1, ?2, ?3, ?4, 0)",
                params![generation_id, osv_id, ecosystem_name, ecosystem.normalize_name(name)],
            )
            .unwrap();
        let package_id = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO osv_affected_versions (affected_package_id, version) VALUES (?1, ?2)",
                params![package_id, version],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn clean_checker_uses_npm_artifacts() {
        let artifact = Artifact::package(Ecosystem::Npm, "lodash", "4.17.21", None);
        assert_eq!(artifact.identity(), "npm:lodash@4.17.21");
    }

    #[test]
    fn nuget_error_mapper_returns_structured_not_found_and_gateway_errors() {
        let missing = nuget_error_response(crate::nuget::NugetError::VersionNotFound(
            "demo@1.0.0".into(),
        ));
        assert_eq!(missing.status, 404);
        let missing_body: Value = serde_json::from_slice(&missing.body).unwrap();
        assert_eq!(missing_body["reason"], "nuget_upstream_error");
        assert_eq!(missing_body["allowed"], false);

        let malformed = nuget_error_response(crate::nuget::NugetError::InvalidMetadata(
            "bad fixture".into(),
        ));
        assert_eq!(malformed.status, 502);
        let malformed_body: Value = serde_json::from_slice(&malformed.body).unwrap();
        assert_eq!(malformed_body["reason"], "nuget_upstream_error");
        assert_ne!(malformed.body, b"null");
    }

    #[tokio::test]
    async fn nuget_route_preserves_upstream_not_found_as_structured_404() {
        let (service_url, _request) = serve_http_once(
            "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string(),
        )
        .await;
        let mut config = Config::default();
        config.upstreams.nuget.service_index_url = service_url;
        let response = router(config)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/nuget/v3/flatcontainer/demo/index.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["reason"], "nuget_upstream_error");
    }
}
