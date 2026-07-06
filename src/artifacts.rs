use crate::config::{ArtifactBehavior, Config};
use crate::response::RegistryResponse;
use axum::body::Body;
use axum::http::{HeaderMap, Response, StatusCode};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
}

impl ArtifactDeliveryClient {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("artifact HTTP client should build with static timeout configuration"),
        }
    }

    pub async fn deliver(
        &self,
        config: &Config,
        upstream_url: String,
        request_headers: Option<&HeaderMap>,
    ) -> Result<ArtifactDeliveryResponse, ArtifactDeliveryError> {
        match config.artifacts.behavior {
            ArtifactBehavior::Redirect => Ok(ArtifactDeliveryResponse::Buffered(
                RegistryResponse::redirect(upstream_url),
            )),
            ArtifactBehavior::Proxy => {
                let mut request = self.client.get(upstream_url);
                if let Some(headers) = request_headers {
                    for name in FORWARDED_REQUEST_HEADERS {
                        if let Some(value) = headers.get(*name) {
                            request = request.header(*name, value.clone());
                        }
                    }
                }
                let response = request.send().await?;
                Ok(ArtifactDeliveryResponse::Streaming(response))
            }
            ArtifactBehavior::ProxyCacheS3 => Err(ArtifactDeliveryError::Unsupported(
                "artifacts.behavior=proxy_cache_s3 is not supported yet".to_string(),
            )),
        }
    }

    pub async fn deliver_registry_response(
        &self,
        config: &Config,
        upstream_url: String,
        request_headers: Option<&HeaderMap>,
    ) -> RegistryResponse {
        match self.deliver(config, upstream_url, request_headers).await {
            Ok(response) => response.into_registry_response().await,
            Err(error) => gateway_error_response(&error),
        }
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
}

impl<'a> ArtifactDeliveryOptions<'a> {
    pub fn new(client: &'a ArtifactDeliveryClient) -> Self {
        Self {
            client,
            request_headers: None,
        }
    }

    pub fn with_request_headers(
        client: &'a ArtifactDeliveryClient,
        request_headers: &'a HeaderMap,
    ) -> Self {
        Self {
            client,
            request_headers: Some(request_headers),
        }
    }
}

pub enum ArtifactDeliveryResponse {
    Buffered(RegistryResponse),
    Streaming(reqwest::Response),
}

impl ArtifactDeliveryResponse {
    pub async fn into_registry_response(self) -> RegistryResponse {
        match self {
            Self::Buffered(response) => response,
            Self::Streaming(response) => match buffered_proxy_response(response).await {
                Ok(response) => response,
                Err(error) => gateway_error_response(&error),
            },
        }
    }

    pub fn into_http_response(self) -> Response<Body> {
        match self {
            Self::Buffered(response) => response.into_http_response(),
            Self::Streaming(response) => streaming_proxy_response(response),
        }
    }
}

#[derive(Debug, Error)]
pub enum ArtifactDeliveryError {
    #[error("unsupported artifact delivery behavior: {0}")]
    Unsupported(String),
    #[error("failed to fetch upstream artifact: {0}")]
    Upstream(#[from] reqwest::Error),
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

fn streaming_proxy_response(response: reqwest::Response) -> Response<Body> {
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
    builder
        .body(Body::from_stream(response.bytes_stream()))
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

    #[tokio::test]
    async fn redirect_behavior_returns_location_without_fetching() {
        let config = Config::default();
        let response = ArtifactDeliveryClient::new()
            .deliver_registry_response(
                &config,
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

        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=0-7".parse().unwrap());
        headers.insert(header::IF_NONE_MATCH, "\"old\"".parse().unwrap());
        headers.insert(header::CONNECTION, "keep-alive".parse().unwrap());
        let response = ArtifactDeliveryClient::new()
            .deliver_registry_response(&config, url, Some(&headers))
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
    async fn proxy_fetch_error_returns_gateway_response() {
        let mut config = Config::default();
        config.artifacts.behavior = ArtifactBehavior::Proxy;

        let response = ArtifactDeliveryClient::new()
            .deliver_registry_response(&config, "not a url".to_string(), None)
            .await;

        assert_eq!(response.status, 502);
        assert_header(&response, "content-type", "application/json");
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["allowed"], false);
        assert_eq!(body["reason"], "artifact_upstream_error");
    }

    async fn serve_once(response: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4096];
            let bytes = stream.read(&mut buffer).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buffer[..bytes]).to_ascii_lowercase()
        });
        (format!("http://{address}/artifact.tgz"), handle)
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
