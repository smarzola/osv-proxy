use crate::artifact::Ecosystem;
use crate::config::{ArtifactBehavior, Config};
use crate::response::RegistryResponse;
use crate::runtime::{BudgetError, RuntimeBudgets};
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use futures_util::{StreamExt, stream};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, Url, redirect};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

const FORWARDED_REQUEST_HEADERS: &[&str] = &[
    "range",
    "if-none-match",
    "if-modified-since",
    "if-range",
    "if-unmodified-since",
];

const FORWARDED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "etag",
    "last-modified",
    "accept-ranges",
    "content-range",
    "cache-control",
    "expires",
];

#[derive(Debug, Clone)]
pub struct ArtifactDeliveryClient {
    client: Client,
    egress: Arc<ArtifactEgressPolicy>,
    budgets: Arc<RuntimeBudgets>,
}

impl ArtifactDeliveryClient {
    pub fn new() -> Self {
        Self::for_config(&Config::default())
    }

    pub fn for_config(config: &Config) -> Self {
        Self::with_budgets(config, Arc::new(RuntimeBudgets::new(&config.limits)))
    }

    pub fn with_budgets(config: &Config, budgets: Arc<RuntimeBudgets>) -> Self {
        Self::build(config, HashMap::new(), budgets)
    }

    fn build(
        config: &Config,
        dns_overrides: HashMap<String, Vec<SocketAddr>>,
        budgets: Arc<RuntimeBudgets>,
    ) -> Self {
        let egress = Arc::new(ArtifactEgressPolicy::from_config(config));
        let resolver = Arc::new(SafeResolver {
            egress: Arc::clone(&egress),
            overrides: dns_overrides,
        });
        Self {
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .read_timeout(READ_TIMEOUT)
                .redirect(redirect::Policy::none())
                .dns_resolver(resolver)
                .no_proxy()
                .build()
                .expect("artifact HTTP client should build with static timeout configuration"),
            egress,
            budgets,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_dns_overrides(
        config: &Config,
        dns_overrides: HashMap<String, Vec<SocketAddr>>,
    ) -> Self {
        Self::build(
            config,
            dns_overrides,
            Arc::new(RuntimeBudgets::new(&config.limits)),
        )
    }

    fn validated_url(
        &self,
        ecosystem: Ecosystem,
        upstream_url: &str,
    ) -> Result<Url, ArtifactDeliveryError> {
        let url = Url::parse(upstream_url).map_err(|error| {
            ArtifactDeliveryError::InvalidUrl(format!("{upstream_url:?}: {error}"))
        })?;
        self.egress
            .validate_url(ecosystem, &url)
            .map_err(ArtifactDeliveryError::ForbiddenDestination)?;
        Ok(url)
    }

    pub async fn deliver(
        &self,
        config: &Config,
        ecosystem: Ecosystem,
        upstream_url: String,
        request_headers: Option<&HeaderMap>,
    ) -> Result<ArtifactDeliveryResponse, ArtifactDeliveryError> {
        let upstream_url = self.validated_url(ecosystem, &upstream_url)?;
        match config.artifacts.behavior {
            ArtifactBehavior::Redirect => Ok(ArtifactDeliveryResponse::Buffered(
                RegistryResponse::redirect(upstream_url.to_string()),
            )),
            ArtifactBehavior::Proxy => {
                let permit = self.budgets.install_egress().await?;
                let mut request = self.client.get(upstream_url);
                if let Some(headers) = request_headers {
                    for name in FORWARDED_REQUEST_HEADERS {
                        if let Some(value) = headers.get(*name) {
                            request = request.header(*name, value.clone());
                        }
                    }
                }
                let response = request.send().await?;
                if is_forbidden_redirect(response.status()) {
                    return Err(ArtifactDeliveryError::UpstreamRedirect(
                        response.status().as_u16(),
                    ));
                }
                if response.status().is_client_error() || response.status().is_server_error() {
                    return Err(ArtifactDeliveryError::UpstreamStatus(
                        response.status().as_u16(),
                    ));
                }
                Ok(ArtifactDeliveryResponse::Streaming(response, permit))
            }
            ArtifactBehavior::ProxyCacheS3 => Err(ArtifactDeliveryError::Unsupported(
                "artifacts.behavior=proxy_cache_s3 is not supported yet".to_string(),
            )),
        }
    }

    pub async fn deliver_head(
        &self,
        config: &Config,
        ecosystem: Ecosystem,
        upstream_url: String,
        request_headers: Option<&HeaderMap>,
    ) -> Result<ArtifactDeliveryResponse, ArtifactDeliveryError> {
        let upstream_url = self.validated_url(ecosystem, &upstream_url)?;
        match config.artifacts.behavior {
            ArtifactBehavior::Redirect => Ok(ArtifactDeliveryResponse::Buffered(
                RegistryResponse::redirect(upstream_url.to_string()),
            )),
            ArtifactBehavior::Proxy => {
                let permit = self.budgets.install_egress().await?;
                let mut request = self.client.head(upstream_url);
                if let Some(headers) = request_headers {
                    for name in FORWARDED_REQUEST_HEADERS {
                        if let Some(value) = headers.get(*name) {
                            request = request.header(*name, value.clone());
                        }
                    }
                }
                let response = request.send().await?;
                if is_forbidden_redirect(response.status()) {
                    return Err(ArtifactDeliveryError::UpstreamRedirect(
                        response.status().as_u16(),
                    ));
                }
                if response.status().is_client_error() || response.status().is_server_error() {
                    return Err(ArtifactDeliveryError::UpstreamStatus(
                        response.status().as_u16(),
                    ));
                }
                Ok(ArtifactDeliveryResponse::Streaming(response, permit))
            }
            ArtifactBehavior::ProxyCacheS3 => Err(ArtifactDeliveryError::Unsupported(
                "artifacts.behavior=proxy_cache_s3 is not supported yet".to_string(),
            )),
        }
    }

    pub async fn deliver_registry_response(
        &self,
        config: &Config,
        ecosystem: Ecosystem,
        upstream_url: String,
        request_headers: Option<&HeaderMap>,
    ) -> RegistryResponse {
        match self
            .deliver(config, ecosystem, upstream_url, request_headers)
            .await
        {
            Ok(response) => response.into_registry_response().await,
            Err(error) => gateway_error_response(&error),
        }
    }

    pub(crate) async fn fetch(
        &self,
        ecosystem: Ecosystem,
        upstream_url: &str,
        total_timeout: Duration,
    ) -> Result<(reqwest::Response, tokio::sync::OwnedSemaphorePermit), ArtifactDeliveryError> {
        let permit = self.budgets.install_egress().await?;
        let upstream_url = self.validated_url(ecosystem, upstream_url)?;
        let response = self
            .client
            .get(upstream_url)
            .timeout(total_timeout)
            .send()
            .await?;
        if is_forbidden_redirect(response.status()) {
            return Err(ArtifactDeliveryError::UpstreamRedirect(
                response.status().as_u16(),
            ));
        }
        if response.status().is_client_error() || response.status().is_server_error() {
            return Err(ArtifactDeliveryError::UpstreamStatus(
                response.status().as_u16(),
            ));
        }
        Ok((response, permit))
    }
}

impl Default for ArtifactDeliveryClient {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct ArtifactDeliveryOptions<'a> {
    pub client: &'a ArtifactDeliveryClient,
    pub request_headers: Option<&'a HeaderMap>,
    pub head: bool,
}

impl<'a> ArtifactDeliveryOptions<'a> {
    pub fn new(client: &'a ArtifactDeliveryClient) -> Self {
        Self {
            client,
            request_headers: None,
            head: false,
        }
    }

    pub fn with_request_headers(
        client: &'a ArtifactDeliveryClient,
        request_headers: &'a HeaderMap,
    ) -> Self {
        Self {
            client,
            request_headers: Some(request_headers),
            head: false,
        }
    }

    pub fn with_request_headers_for_head(
        client: &'a ArtifactDeliveryClient,
        request_headers: &'a HeaderMap,
    ) -> Self {
        Self {
            client,
            request_headers: Some(request_headers),
            head: true,
        }
    }
}

pub enum ArtifactDeliveryResponse {
    Buffered(RegistryResponse),
    Streaming(reqwest::Response, tokio::sync::OwnedSemaphorePermit),
}

impl ArtifactDeliveryResponse {
    pub async fn into_registry_response(self) -> RegistryResponse {
        match self {
            Self::Buffered(response) => response,
            Self::Streaming(response, _permit) => match buffered_proxy_response(response).await {
                Ok(response) => response,
                Err(error) => gateway_error_response(&error),
            },
        }
    }

    pub fn into_http_response(self) -> Response<Body> {
        match self {
            Self::Buffered(response) => response.into_http_response(),
            Self::Streaming(response, permit) => streaming_proxy_response(response, permit),
        }
    }
}

#[derive(Debug, Error)]
pub enum ArtifactDeliveryError {
    #[error("upstream artifact concurrency limit failed: {0}")]
    Budget(#[from] BudgetError),
    #[error("unsupported artifact delivery behavior: {0}")]
    Unsupported(String),
    #[error("invalid upstream artifact URL: {0}")]
    InvalidUrl(String),
    #[error("forbidden upstream artifact destination: {0}")]
    ForbiddenDestination(String),
    #[error("failed to fetch upstream artifact: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("upstream artifact returned HTTP status {0}")]
    UpstreamStatus(u16),
    #[error("upstream artifact returned forbidden redirect status {0}")]
    UpstreamRedirect(u16),
}

#[derive(Debug)]
struct ArtifactEgressPolicy {
    trusted_origins: HashMap<Ecosystem, BTreeSet<String>>,
    globally_trusted_origins: BTreeSet<String>,
    trusted_hosts: BTreeSet<String>,
}

impl ArtifactEgressPolicy {
    fn from_config(config: &Config) -> Self {
        let configured = [
            (Ecosystem::Npm, config.upstreams.npm.registry_url.as_str()),
            (Ecosystem::Pypi, config.upstreams.pypi.simple_url.as_str()),
            (Ecosystem::Go, config.upstreams.go.proxy_url.as_str()),
            (
                Ecosystem::CratesIo,
                config.upstreams.cargo.sparse_index_url.as_str(),
            ),
            (
                Ecosystem::CratesIo,
                config.upstreams.cargo.download_url.as_str(),
            ),
            (
                Ecosystem::Nuget,
                config.upstreams.nuget.service_index_url.as_str(),
            ),
            (
                Ecosystem::RubyGems,
                config.upstreams.rubygems.registry_url.as_str(),
            ),
            (
                Ecosystem::Maven,
                config.upstreams.maven.repository_url.as_str(),
            ),
        ];
        let mut trusted_origins = HashMap::<Ecosystem, BTreeSet<String>>::new();
        let mut globally_trusted_origins = BTreeSet::new();
        let mut trusted_hosts = BTreeSet::new();
        for (ecosystem, value) in configured {
            let Ok(url) = Url::parse(value) else { continue };
            if let Some(origin) = normalized_origin(&url) {
                trusted_origins.entry(ecosystem).or_default().insert(origin);
            }
            if let Some(host) = url.host_str() {
                trusted_hosts.insert(host.to_ascii_lowercase());
            }
        }
        for value in &config.artifacts.trusted_origins {
            let Ok(url) = Url::parse(value) else { continue };
            if let Some(origin) = normalized_origin(&url) {
                globally_trusted_origins.insert(origin);
            }
            if let Some(host) = url.host_str() {
                trusted_hosts.insert(host.to_ascii_lowercase());
            }
        }
        Self {
            trusted_origins,
            globally_trusted_origins,
            trusted_hosts,
        }
    }

    fn validate_url(&self, ecosystem: Ecosystem, url: &Url) -> Result<(), String> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err("URLs containing credentials are not allowed".to_string());
        }
        if url.fragment().is_some() {
            return Err("URL fragments are not allowed".to_string());
        }
        let origin = normalized_origin(url)
            .ok_or_else(|| "URL must use http or https and contain a host".to_string())?;
        let trusted_origin = self.globally_trusted_origins.contains(&origin)
            || self
                .trusted_origins
                .get(&ecosystem)
                .is_some_and(|origins| origins.contains(&origin));
        if url.scheme() == "http" && !trusted_origin {
            return Err("unencrypted HTTP is allowed only for a configured trusted origin".into());
        }
        let host = url
            .host_str()
            .ok_or_else(|| "artifact URL has no host".to_string())?;
        if self.host_is_trusted(host) && !trusted_origin {
            return Err(format!(
                "configured trusted host {host} may be used only through an exact configured origin"
            ));
        }
        if host.eq_ignore_ascii_case("localhost") && !trusted_origin {
            return Err("localhost is not a trusted artifact origin".to_string());
        }
        let host_without_ipv6_brackets = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host_without_ipv6_brackets.parse::<IpAddr>()
            && is_forbidden_ip(ip)
            && !trusted_origin
        {
            return Err(format!(
                "non-public address {ip} is not a trusted artifact origin"
            ));
        }
        Ok(())
    }

    fn host_is_trusted(&self, host: &str) -> bool {
        self.trusted_hosts.contains(&host.to_ascii_lowercase())
    }
}

fn normalized_origin(url: &Url) -> Option<String> {
    matches!(url.scheme(), "http" | "https")
        .then(|| url.origin().ascii_serialization())
        .filter(|origin| origin != "null")
}

struct SafeResolver {
    egress: Arc<ArtifactEgressPolicy>,
    overrides: HashMap<String, Vec<SocketAddr>>,
}

impl Resolve for SafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_ascii_lowercase();
        let trusted = self.egress.host_is_trusted(&host);
        let override_addrs = self.overrides.get(&host).cloned();
        Box::pin(async move {
            let addresses = if let Some(addresses) = override_addrs {
                addresses
            } else {
                tokio::net::lookup_host((host.as_str(), 0))
                    .await?
                    .collect::<Vec<_>>()
            };
            if addresses.is_empty() {
                return Err(io_error(format!("DNS returned no addresses for {host}")));
            }
            if !trusted
                && let Some(address) = addresses
                    .iter()
                    .find(|address| is_forbidden_ip(address.ip()))
            {
                return Err(io_error(format!(
                    "DNS for {host} returned forbidden non-public address {}",
                    address.ip()
                )));
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

fn io_error(message: String) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(io::Error::other(message))
}

fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_forbidden_ipv4(ip),
        IpAddr::V6(ip) => is_forbidden_ipv6(ip),
    }
}

fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0 && d != 9 && d != 10)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
}

fn is_forbidden_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_forbidden_ipv4(ipv4);
    }
    let segments = ip.segments();
    let value = u128::from_be_bytes(ip.octets());
    let globally_reachable_translation = matches!(segments, [0x64, 0xff9b, 0, 0, 0, 0, _, _]);
    let allocated_global_unicast = segments[0] & 0xe000 == 0x2000;
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (!globally_reachable_translation && !allocated_global_unicast)
        || matches!(segments, [0x64, 0xff9b, 1, _, _, _, _, _])
        || matches!(segments, [0x100, 0, 0, 0, _, _, _, _])
        || matches!(segments, [0x100, 0, 0, 1, _, _, _, _])
        || (matches!(segments, [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(value == 0x2001_0001_0000_0000_0000_0000_0000_0001
                || value == 0x2001_0001_0000_0000_0000_0000_0000_0002
                || value == 0x2001_0001_0000_0000_0000_0000_0000_0003
                || matches!(segments, [0x2001, 3, _, _, _, _, _, _])
                || matches!(segments, [0x2001, 4, 0x112, _, _, _, _, _])
                || matches!(segments, [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3f).contains(&b))))
        || matches!(segments, [0x2002, _, _, _, _, _, _, _])
        || matches!(segments, [0x2001, 0x0db8, _, _, _, _, _, _])
        || matches!(segments, [0x3fff, 0..=0x0fff, _, _, _, _, _, _])
        || matches!(segments, [0x5f00, ..])
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
}

fn is_forbidden_redirect(status: StatusCode) -> bool {
    status.is_redirection() && status != StatusCode::NOT_MODIFIED
}

pub fn gateway_error_response(error: &ArtifactDeliveryError) -> RegistryResponse {
    let body = json!({
        "allowed": false,
        "reason": "artifact_upstream_error",
        "message": error.to_string(),
    });
    RegistryResponse::json(502, &body).expect("static artifact gateway response should serialize")
}

async fn buffered_proxy_response(
    response: reqwest::Response,
) -> Result<RegistryResponse, ArtifactDeliveryError> {
    let status = response.status().as_u16();
    let headers = forwarded_response_headers(response.headers());
    let body = response.bytes().await?.to_vec();
    Ok(RegistryResponse {
        status,
        headers,
        body,
    })
}

fn streaming_proxy_response(
    response: reqwest::Response,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Response<Body> {
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    let headers = builder
        .headers_mut()
        .expect("headers are available before response body is built");
    for (name, value) in response.headers() {
        if is_forwarded_response_header(name.as_str()) {
            headers.insert(name, value.clone());
        }
    }
    let stream = stream::unfold(
        (response.bytes_stream(), permit),
        |(mut body, permit)| async move { body.next().await.map(|result| (result, (body, permit))) },
    );
    builder
        .body(Body::from_stream(stream))
        .expect("artifact response should convert to HTTP response")
}

fn forwarded_response_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| is_forwarded_response_header(name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

fn is_forwarded_response_header(name: &str) -> bool {
    FORWARDED_RESPONSE_HEADERS
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration as TokioDuration, timeout};

    #[tokio::test]
    async fn redirect_behavior_returns_location_without_fetching() {
        let mut config = Config::default();
        config
            .artifacts
            .trusted_origins
            .push("http://127.0.0.1:1".to_string());
        let response = ArtifactDeliveryClient::for_config(&config)
            .deliver_registry_response(
                &config,
                Ecosystem::Npm,
                "http://127.0.0.1:1/not-contacted.tgz".to_string(),
                None,
            )
            .await;

        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            vec![(
                "location".to_string(),
                "http://127.0.0.1:1/not-contacted.tgz".to_string()
            )]
        );
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn proxy_behavior_forwards_selected_headers_and_buffers_for_tests() {
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        let (url, request) = serve_once(
            "HTTP/1.1 206 Partial Content\r\n\
             content-type: application/octet-stream\r\n\
             content-length: 8\r\n\
             etag: \"abc\"\r\n\
             last-modified: Wed, 01 Jul 2026 00:00:00 GMT\r\n\
             accept-ranges: bytes\r\n\
             content-range: bytes 0-7/8\r\n\
             cache-control: public, max-age=60\r\n\
             connection: close\r\n\
             x-secret: hidden\r\n\
             \r\n\
             artifact",
        )
        .await;
        trust_url(&mut config, &url);

        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=0-7".parse().unwrap());
        headers.insert(header::IF_NONE_MATCH, "\"old\"".parse().unwrap());
        headers.insert(header::CONNECTION, "keep-alive".parse().unwrap());
        let response = ArtifactDeliveryClient::for_config(&config)
            .deliver_registry_response(&config, Ecosystem::Npm, url, Some(&headers))
            .await;
        let upstream_request = request.await.unwrap();

        assert_eq!(response.status, 206);
        assert_eq!(response.body, b"artifact");
        assert_header(&response, "content-type", "application/octet-stream");
        assert_header(&response, "content-length", "8");
        assert_header(&response, "etag", "\"abc\"");
        assert_header(&response, "last-modified", "Wed, 01 Jul 2026 00:00:00 GMT");
        assert_header(&response, "accept-ranges", "bytes");
        assert_header(&response, "content-range", "bytes 0-7/8");
        assert_header(&response, "cache-control", "public, max-age=60");
        assert!(header_value(&response, "connection").is_none());
        assert!(header_value(&response, "x-secret").is_none());
        assert!(upstream_request.contains("range: bytes=0-7"));
        assert!(upstream_request.contains("if-none-match: \"old\""));
        assert!(!upstream_request.contains("connection: keep-alive"));
    }

    #[tokio::test]
    async fn streaming_response_holds_egress_permit_until_body_is_dropped() {
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        config.limits.egress_requests = 1;
        config.limits.queue_timeout = TokioDuration::from_millis(10);
        let (url, request) =
            serve_once("HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nartifact")
                .await;
        trust_url(&mut config, &url);
        let budgets = Arc::new(RuntimeBudgets::new(&config.limits));
        let client = ArtifactDeliveryClient::with_budgets(&config, Arc::clone(&budgets));

        let response = client
            .deliver(&config, Ecosystem::Npm, url, None)
            .await
            .unwrap()
            .into_http_response();
        request.await.unwrap();
        assert_eq!(
            budgets.install_egress().await.unwrap_err(),
            BudgetError::EgressSaturated
        );

        drop(response);
        assert!(budgets.install_egress().await.is_ok());
    }

    #[tokio::test]
    async fn proxy_fetch_error_returns_gateway_response() {
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;

        let response = ArtifactDeliveryClient::new()
            .deliver_registry_response(&config, Ecosystem::Npm, "not a url".to_string(), None)
            .await;

        assert_eq!(response.status, 502);
        assert_header(&response, "content-type", "application/json");
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["allowed"], false);
        assert_eq!(body["reason"], "artifact_upstream_error");
    }

    #[tokio::test]
    async fn proxy_upstream_http_error_returns_gateway_response() {
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        let (url, request) = serve_once(
            "HTTP/1.1 404 Not Found\r\n\
             content-type: text/plain\r\n\
             content-length: 9\r\n\
             connection: close\r\n\
             \r\n\
             not found",
        )
        .await;
        trust_url(&mut config, &url);

        let response = ArtifactDeliveryClient::for_config(&config)
            .deliver_registry_response(&config, Ecosystem::Npm, url, None)
            .await;
        let upstream_request = request.await.unwrap();

        assert_eq!(response.status, 502);
        assert_header(&response, "content-type", "application/json");
        assert!(
            !response
                .body
                .windows(b"not found".len())
                .any(|window| window == b"not found")
        );
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["allowed"], false);
        assert_eq!(body["reason"], "artifact_upstream_error");
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("HTTP status 404")
        );
        assert!(upstream_request.starts_with("get /artifact.tgz "));
    }

    #[test]
    fn rejects_unsafe_schemes_credentials_and_literal_addresses() {
        let client = ArtifactDeliveryClient::new();
        for url in [
            "file:///etc/passwd",
            "ftp://example.com/file",
            "https://user:secret@example.com/file",
            "https://127.0.0.1/file",
            "https://10.0.0.1/file",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/file",
            "https://[fe80::1]/file",
            "https://[fc00::1]/file",
            "https://[::ffff:127.0.0.1]/file",
            "https://[64:ff9b:1::1]/file",
            "https://[100::1]/file",
            "https://[100:0:0:1::1]/file",
            "https://[2001:2::1]/file",
            "https://[2001:db8::1]/file",
            "https://[3fff::1]/file",
            "https://[5f00::1]/file",
            "https://[fec0::1]/file",
            "https://192.88.99.2/file",
        ] {
            assert!(
                client.validated_url(Ecosystem::Npm, url).is_err(),
                "unsafe URL was accepted: {url}"
            );
        }
        assert!(
            client
                .validated_url(
                    Ecosystem::Npm,
                    "https://cdn.example/artifact.tgz?signature=abc",
                )
                .is_ok()
        );
    }

    #[test]
    fn accepts_precise_globally_reachable_iana_exceptions() {
        let client = ArtifactDeliveryClient::new();
        for url in [
            "https://192.0.0.9/file",
            "https://192.0.0.10/file",
            "https://[64:ff9b::1]/file",
            "https://[2001:1::1]/file",
            "https://[2001:1::2]/file",
            "https://[2001:1::3]/file",
            "https://[2001:3::1]/file",
            "https://[2001:4:112::1]/file",
            "https://[2001:20::1]/file",
            "https://[2001:2f::1]/file",
            "https://[2001:30::1]/file",
            "https://[2001:3f::1]/file",
        ] {
            assert!(
                client.validated_url(Ecosystem::Npm, url).is_ok(),
                "globally reachable IANA exception was rejected: {url}"
            );
        }
    }

    #[tokio::test]
    async fn private_dns_answer_is_rejected_before_contact() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut overrides = HashMap::new();
        overrides.insert("metadata.test".to_string(), vec![address]);
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        let client = ArtifactDeliveryClient::with_dns_overrides(&config, overrides);

        let response = client
            .deliver_registry_response(
                &config,
                Ecosystem::Npm,
                format!("https://metadata.test:{}/artifact.tgz", address.port()),
                None,
            )
            .await;

        assert_eq!(response.status, 502);
        assert!(
            timeout(TokioDuration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn special_use_dns_answers_are_rejected() {
        for address in [
            "192.88.99.2:443",
            "[64:ff9b:1::1]:443",
            "[100::1]:443",
            "[100:0:0:1::1]:443",
            "[2001:2::1]:443",
            "[2001:db8::1]:443",
            "[3fff::1]:443",
            "[5f00::1]:443",
            "[fec0::1]:443",
        ] {
            let mut config = Config::default();
            config.artifacts.behavior = ArtifactBehavior::Proxy;
            let client = ArtifactDeliveryClient::with_dns_overrides(
                &config,
                HashMap::from([(
                    "special.test".to_string(),
                    vec![address.parse::<SocketAddr>().unwrap()],
                )]),
            );

            let response = client
                .deliver_registry_response(
                    &config,
                    Ecosystem::Npm,
                    "https://special.test/artifact.tgz".to_string(),
                    None,
                )
                .await;

            assert_eq!(response.status, 502, "accepted DNS answer {address}");
        }
    }

    #[tokio::test]
    async fn explicitly_trusted_private_origin_is_reachable() {
        let (url, request) =
            serve_once("HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nartifact")
                .await;
        let parsed = Url::parse(&url).unwrap();
        let port = parsed.port().unwrap();
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        config
            .artifacts
            .trusted_origins
            .push(format!("http://trusted.test:{port}"));
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let client = ArtifactDeliveryClient::with_dns_overrides(
            &config,
            HashMap::from([("trusted.test".to_string(), vec![address])]),
        );

        let response = client
            .deliver_registry_response(
                &config,
                Ecosystem::Npm,
                format!("http://trusted.test:{port}/artifact.tgz"),
                None,
            )
            .await;

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"artifact");
        assert!(request.await.unwrap().starts_with("get /artifact.tgz "));
    }

    #[tokio::test]
    async fn disabled_redirect_does_not_contact_private_target() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/secret", target.local_addr().unwrap());
        let response_text = format!(
            "HTTP/1.1 302 Found\r\nlocation: {target_url}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        let (initial_url, initial_request) = serve_once(response_text).await;
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;
        trust_url(&mut config, &initial_url);
        let client = ArtifactDeliveryClient::for_config(&config);

        let response = client
            .deliver_registry_response(&config, Ecosystem::Npm, initial_url, None)
            .await;

        assert_eq!(response.status, 502);
        assert!(
            initial_request
                .await
                .unwrap()
                .starts_with("get /artifact.tgz ")
        );
        assert!(
            timeout(TokioDuration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn conditional_get_and_head_preserve_not_modified() {
        for head in [false, true] {
            let (url, request) = serve_once(
                "HTTP/1.1 304 Not Modified\r\netag: \"current\"\r\nconnection: close\r\n\r\n",
            )
            .await;
            let mut config = Config::default();
            config.artifacts.behavior = ArtifactBehavior::Proxy;
            trust_url(&mut config, &url);
            let client = ArtifactDeliveryClient::for_config(&config);
            let mut headers = HeaderMap::new();
            headers.insert(header::IF_NONE_MATCH, "\"current\"".parse().unwrap());

            let response = if head {
                client
                    .deliver_head(&config, Ecosystem::Npm, url, Some(&headers))
                    .await
            } else {
                client
                    .deliver(&config, Ecosystem::Npm, url, Some(&headers))
                    .await
            }
            .unwrap()
            .into_registry_response()
            .await;

            assert_eq!(response.status, 304);
            assert_header(&response, "etag", "\"current\"");
            let request = request.await.unwrap();
            assert!(request.starts_with(if head { "head " } else { "get " }));
            assert!(request.contains("if-none-match: \"current\""));
        }
    }

    #[test]
    fn configured_private_origin_is_scoped_to_its_ecosystem() {
        let mut config = Config::default();
        config.upstreams.maven.repository_url = "http://127.0.0.1:9000".to_string();
        let client = ArtifactDeliveryClient::for_config(&config);
        assert!(
            client
                .validated_url(Ecosystem::Maven, "http://127.0.0.1:9000/file.jar")
                .is_ok()
        );
        assert!(
            client
                .validated_url(Ecosystem::Npm, "http://127.0.0.1:9000/file.tgz")
                .is_err()
        );
        assert!(
            client
                .validated_url(Ecosystem::Maven, "http://127.0.0.1:9001/file.jar")
                .is_err()
        );
    }

    async fn serve_once(response: impl Into<String>) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let response = response.into();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4096];
            let bytes = stream.read(&mut buffer).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buffer[..bytes]).to_ascii_lowercase()
        });
        (format!("http://{address}/artifact.tgz"), handle)
    }

    fn trust_url(config: &mut Config, value: &str) {
        let url = Url::parse(value).unwrap();
        config
            .artifacts
            .trusted_origins
            .push(url.origin().ascii_serialization());
    }

    fn assert_header(response: &RegistryResponse, name: &str, expected: &str) {
        assert_eq!(header_value(response, name).as_deref(), Some(expected));
    }

    fn header_value(response: &RegistryResponse, name: &str) -> Option<String> {
        response
            .headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }
}
