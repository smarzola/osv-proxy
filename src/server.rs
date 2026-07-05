use crate::config::Config;
use crate::malicious::{MaliciousChecker, OsvHttpClient};
use crate::npm::{self, NpmMetadataProvider, NpmRegistryClient, NpmResponse};
use chrono::{DateTime, Utc};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub fn serve(config: &Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.server.listen)?;
    println!(
        "serving phase-one redirect proxy on {}",
        listener.local_addr()?
    );

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(err) = handle_stream(config, &mut stream) {
                    eprintln!("request handling failed: {err}");
                }
            }
            Err(err) => eprintln!("connection failed: {err}"),
        }
    }

    Ok(())
}

fn handle_stream(config: &Config, stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut buffer = [0_u8; 8192];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let response = route_request(config, method, path);
    write_response(stream, response)?;
    Ok(())
}

pub fn route_request(config: &Config, method: &str, path: &str) -> NpmResponse {
    let upstream = NpmRegistryClient::new(&config.upstreams.npm.registry_url);
    let checker = OsvHttpClient::new(&config.policy.malicious.osv_api_url);
    route_request_with_upstream(config, method, path, Utc::now(), &checker, &upstream)
}

pub fn route_request_with_upstream(
    config: &Config,
    method: &str,
    path: &str,
    now: DateTime<Utc>,
    checker: &dyn MaliciousChecker,
    upstream: &dyn NpmMetadataProvider,
) -> NpmResponse {
    if method != "GET" {
        return simple_response(405, "method not allowed");
    }

    match parse_npm_route(path) {
        Some(NpmRoute::Metadata { package }) => {
            npm::metadata_response(config, upstream, checker, &package, now)
                .unwrap_or_else(|err| npm::error_response(&err))
        }
        Some(NpmRoute::Artifact { package, tarball }) => {
            npm::artifact_response(config, upstream, checker, &package, &tarball, now)
                .unwrap_or_else(|err| npm::error_response(&err))
        }
        None => simple_response(404, "not found"),
    }
}

fn write_response(stream: &mut TcpStream, response: NpmResponse) -> std::io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        302 => "Found",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    };
    write!(stream, "HTTP/1.1 {} {}\r\n", response.status, reason)?;
    write!(stream, "content-length: {}\r\n", response.body.len())?;
    for (name, value) in response.headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "connection: close\r\n\r\n")?;
    stream.write_all(&response.body)?;
    Ok(())
}

fn simple_response(status: u16, message: &str) -> NpmResponse {
    let body = serde_json::json!({ "message": message });
    NpmResponse::json(status, &body).expect("static server response should serialize")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NpmRoute {
    Metadata { package: String },
    Artifact { package: String, tarball: String },
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
    use crate::malicious::{MaliciousError, MaliciousHit};
    use crate::npm::NpmError;
    use serde_json::{json, Value};
    use std::collections::HashMap;

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

    impl NpmMetadataProvider for StaticUpstream {
        fn fetch_package_metadata(&self, package: &str) -> Result<Value, NpmError> {
            self.metadata.get(package).cloned().ok_or_else(|| {
                NpmError::InvalidMetadata(format!("missing static metadata for {package}"))
            })
        }
    }

    struct CleanChecker;

    impl MaliciousChecker for CleanChecker {
        fn check(&self, _artifact: &Artifact) -> Result<Vec<MaliciousHit>, MaliciousError> {
            Ok(Vec::new())
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn parses_documented_npm_routes() {
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

    #[test]
    fn parses_encoded_scoped_npm_metadata_route() {
        assert_eq!(
            parse_npm_route("/npm/@babel%2Fcore?write=true"),
            Some(NpmRoute::Metadata {
                package: "@babel/core".to_string()
            })
        );
    }

    #[test]
    fn routes_npm_metadata_with_mocked_upstream() {
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
        );

        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            body["versions"]["4.17.21"]["dist"]["tarball"],
            "http://127.0.0.1:8080/npm/lodash/-/lodash-4.17.21.tgz"
        );
    }

    #[test]
    fn routes_npm_artifact_with_mocked_upstream() {
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
        );

        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            vec![(
                "location".to_string(),
                "https://registry.example/@babel/core/-/core-7.24.0.tgz".to_string()
            )]
        );
    }

    #[test]
    fn method_mismatch_returns_405() {
        let response = route_request_with_upstream(
            &Config::default(),
            "POST",
            "/npm/lodash",
            now(),
            &CleanChecker,
            &StaticUpstream::with("lodash", json!({})),
        );
        assert_eq!(response.status, 405);
    }

    #[test]
    fn clean_checker_uses_npm_artifacts() {
        let artifact = Artifact::package(Ecosystem::Npm, "lodash", "4.17.21", None);
        assert_eq!(artifact.identity(), "npm:lodash@4.17.21");
    }
}
