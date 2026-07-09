use osv_proxy::artifact::Ecosystem;
use osv_proxy::config::{ArtifactBehavior, BlocklistEntry, Config};
use osv_proxy::response::RegistryResponse;
use osv_proxy::server;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NPM_PACKAGE: &str = "osv-proxy-e2e-npm";
const PYPI_PACKAGE: &str = "osv-proxy-e2e-pypi";
const PYPI_MODULE: &str = "osv_proxy_e2e_pypi";
const CARGO_PACKAGE: &str = "osv-proxy-e2e-cargo";

#[test]
fn cargo_source_replacement_supports_redirect_and_proxy_and_rejects_blocked_versions() {
    require_command("cargo");
    let workspace = TempWorkspace::new("cargo-install-e2e");
    let fixture = FixtureArtifacts::create(workspace.path());
    let upstream = start_fixture_upstream(fixture);

    for behavior in [ArtifactBehavior::Redirect, ArtifactBehavior::Proxy] {
        let proxy = start_proxy_with_behavior(upstream.base_url(), behavior);
        let allowed = workspace.child(match behavior {
            ArtifactBehavior::Redirect => "cargo-redirect",
            _ => "cargo-proxy",
        });
        cargo_project(&allowed, "1.0.0");
        write_cargo_source_replacement(&allowed, &proxy.base_url());
        let output = Command::new("cargo")
            .arg("build")
            .current_dir(&allowed)
            .output()
            .unwrap();
        assert_success("cargo build allowed package", &output);
    }

    let proxy = start_proxy_with_behavior(upstream.base_url(), ArtifactBehavior::Redirect);
    let blocked = workspace.child("cargo-blocked");
    cargo_project(&blocked, "1.0.1");
    write_cargo_source_replacement(&blocked, &proxy.base_url());
    let output = Command::new("cargo")
        .arg("build")
        .current_dir(&blocked)
        .output()
        .unwrap();
    assert_failure("cargo build blocked package", &output);

    let locked = workspace.child("cargo-locked-blocked");
    cargo_project(&locked, "1.0.1");
    write_cargo_source_replacement_url(&locked, &format!("sparse+{}/", upstream.base_url()));
    let output = Command::new("cargo")
        .arg("generate-lockfile")
        .current_dir(&locked)
        .output()
        .unwrap();
    assert_success("cargo generate lockfile for fixture", &output);
    write_cargo_source_replacement(&locked, &proxy.base_url());
    let output = Command::new("cargo")
        .args(["build", "--locked"])
        .current_dir(&locked)
        .output()
        .unwrap();
    assert_failure("cargo build blocked lockfile package", &output);
}

#[test]
fn npm_install_uses_proxy_for_allowed_and_blocked_versions() {
    require_command("npm");
    let workspace = TempWorkspace::new("npm-install-e2e");
    let fixture = FixtureArtifacts::create(workspace.path());
    let upstream = start_fixture_upstream(fixture);
    let proxy = start_proxy(upstream.base_url());

    let allowed_project = workspace.child("npm-allowed");
    fs::create_dir_all(&allowed_project).unwrap();
    write_file(
        &allowed_project.join("package.json"),
        r#"{"private":true,"dependencies":{}}"#,
    );

    let allowed = Command::new("npm")
        .arg("install")
        .arg("--registry")
        .arg(format!("{}/npm/", proxy.base_url()))
        .arg("--ignore-scripts")
        .arg("--audit=false")
        .arg("--fund=false")
        .arg("--package-lock=false")
        .arg("--cache")
        .arg(workspace.child("npm-cache"))
        .arg(format!("{NPM_PACKAGE}@1.0.0"))
        .current_dir(&allowed_project)
        .output()
        .unwrap();
    assert_success("npm install allowed package", &allowed);
    assert!(
        allowed_project
            .join("node_modules")
            .join(NPM_PACKAGE)
            .join("package.json")
            .exists()
    );

    let blocked_project = workspace.child("npm-blocked");
    fs::create_dir_all(&blocked_project).unwrap();
    write_file(
        &blocked_project.join("package.json"),
        r#"{"private":true,"dependencies":{}}"#,
    );
    let blocked = Command::new("npm")
        .arg("install")
        .arg("--registry")
        .arg(format!("{}/npm/", proxy.base_url()))
        .arg("--ignore-scripts")
        .arg("--audit=false")
        .arg("--fund=false")
        .arg("--package-lock=false")
        .arg("--cache")
        .arg(workspace.child("npm-cache-blocked"))
        .arg(format!("{NPM_PACKAGE}@1.0.1"))
        .current_dir(&blocked_project)
        .output()
        .unwrap();
    assert_failure("npm install blocked package", &blocked);
    assert!(
        !blocked_project
            .join("node_modules")
            .join(NPM_PACKAGE)
            .exists()
    );
}

#[test]
fn uv_pip_install_uses_proxy_for_allowed_and_blocked_versions() {
    require_command("uv");
    require_command("zip");
    let workspace = TempWorkspace::new("uv-pip-install-e2e");
    let fixture = FixtureArtifacts::create(workspace.path());
    let upstream = start_fixture_upstream(fixture);
    let proxy = start_proxy(upstream.base_url());

    let allowed_target = workspace.child("uv-allowed-target");
    let allowed = Command::new("uv")
        .arg("pip")
        .arg("install")
        .arg("--target")
        .arg(&allowed_target)
        .arg("--index-url")
        .arg(format!("{}/pypi/simple/", proxy.base_url()))
        .arg("--no-deps")
        .arg("--cache-dir")
        .arg(workspace.child("uv-cache"))
        .arg(format!("{PYPI_PACKAGE}==1.0.0"))
        .output()
        .unwrap();
    assert_success("uv pip install allowed package", &allowed);
    assert!(
        allowed_target
            .join(PYPI_MODULE)
            .join("__init__.py")
            .exists()
    );

    let blocked_target = workspace.child("uv-blocked-target");
    let blocked = Command::new("uv")
        .arg("pip")
        .arg("install")
        .arg("--target")
        .arg(&blocked_target)
        .arg("--index-url")
        .arg(format!("{}/pypi/simple/", proxy.base_url()))
        .arg("--no-deps")
        .arg("--cache-dir")
        .arg(workspace.child("uv-cache-blocked"))
        .arg(format!("{PYPI_PACKAGE}==1.0.1"))
        .output()
        .unwrap();
    assert_failure("uv pip install blocked package", &blocked);
    assert!(!blocked_target.join(PYPI_MODULE).exists());
}

struct FixtureArtifacts {
    npm_tarballs: HashMap<String, Vec<u8>>,
    pypi_wheels: HashMap<String, Vec<u8>>,
    cargo_crates: HashMap<String, Vec<u8>>,
}

impl FixtureArtifacts {
    fn create(root: &Path) -> Self {
        Self {
            npm_tarballs: create_npm_tarballs(root),
            pypi_wheels: create_pypi_wheels(root),
            cargo_crates: create_cargo_crates(root),
        }
    }
}

fn start_fixture_upstream(fixture: FixtureArtifacts) -> TestServer {
    let fixture = Arc::new(fixture);
    start_http_server(move |base_url| {
        let fixture = Arc::clone(&fixture);
        Arc::new(move |request| fixture_response(&fixture, &base_url, request))
    })
}

fn start_proxy(upstream_base_url: String) -> TestServer {
    start_proxy_with_behavior(upstream_base_url, ArtifactBehavior::Redirect)
}

fn start_proxy_with_behavior(upstream_base_url: String, behavior: ArtifactBehavior) -> TestServer {
    start_http_server(move |proxy_base_url| {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        Arc::new(move |request| {
            let runtime = Arc::clone(&runtime);
            let mut config = Config::default();
            config.server.public_base_url = proxy_base_url.clone();
            config.upstreams.npm.registry_url = upstream_base_url.clone();
            config.upstreams.pypi.simple_url = format!("{upstream_base_url}/simple");
            config.upstreams.cargo.sparse_index_url = upstream_base_url.clone();
            config.upstreams.cargo.download_url = format!("{upstream_base_url}/cargo-files");
            config.artifacts.behavior = behavior;
            config.policy.osv.api_url = upstream_base_url.clone();
            config.blocklist.push(BlocklistEntry {
                ecosystem: Ecosystem::Npm,
                name: NPM_PACKAGE.to_string(),
                versions: vec!["1.0.1".to_string()],
                reason: "package-manager e2e blocked npm version".to_string(),
            });
            config.blocklist.push(BlocklistEntry {
                ecosystem: Ecosystem::CratesIo,
                name: CARGO_PACKAGE.to_string(),
                versions: vec!["1.0.1".to_string()],
                reason: "package-manager e2e blocked Cargo version".to_string(),
            });
            config.blocklist.push(BlocklistEntry {
                ecosystem: Ecosystem::Pypi,
                name: PYPI_PACKAGE.to_string(),
                versions: vec!["1.0.1".to_string()],
                reason: "package-manager e2e blocked pypi version".to_string(),
            });

            runtime.block_on(server::route_request_with_accept(
                &config,
                &request.method,
                &request.path,
                request.header("accept"),
            ))
        })
    })
}

fn fixture_response(
    fixture: &FixtureArtifacts,
    base_url: &str,
    request: HttpRequest,
) -> RegistryResponse {
    let path = request.path.split('?').next().unwrap_or(&request.path);
    if request.method == "POST" && path == "/v1/query" {
        return RegistryResponse::json(200, &json!({ "vulns": [] })).unwrap();
    }
    if request.method == "POST" && path == "/v1/querybatch" {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body).unwrap();
        let query_count = body["queries"].as_array().map(Vec::len).unwrap_or_default();
        return RegistryResponse::json(
            200,
            &json!({ "results": vec![json!({ "vulns": [] }); query_count] }),
        )
        .unwrap();
    }

    if request.method == "GET" && path == format!("/{NPM_PACKAGE}") {
        return RegistryResponse::json(
            200,
            &json!({
                "name": NPM_PACKAGE,
                "dist-tags": { "latest": "1.0.1", "stable": "1.0.0" },
                "time": {
                    "1.0.0": "2026-06-01T00:00:00Z",
                    "1.0.1": "2026-06-01T00:00:00Z"
                },
                "versions": {
                    "1.0.0": npm_version_metadata(base_url, "1.0.0"),
                    "1.0.1": npm_version_metadata(base_url, "1.0.1")
                }
            }),
        )
        .unwrap();
    }

    if request.method == "GET" {
        if path == "/config.json" {
            return RegistryResponse::json(
                200,
                &json!({ "dl": format!("{base_url}/cargo-files") }),
            )
            .unwrap();
        }
        if let Some(filename) = path.strip_prefix("/npm-files/")
            && let Some(body) = fixture.npm_tarballs.get(filename)
        {
            return binary_response("application/octet-stream", body.clone());
        }

        if path == format!("/simple/{PYPI_PACKAGE}/") {
            return RegistryResponse::json(
                200,
                &json!({
                    "meta": { "api-version": "1.1" },
                    "name": PYPI_PACKAGE,
                    "versions": ["1.0.0", "1.0.1"],
                    "files": [
                        pypi_file_metadata(base_url, "1.0.0"),
                        pypi_file_metadata(base_url, "1.0.1")
                    ]
                }),
            )
            .unwrap();
        }

        if let Some(filename) = path.strip_prefix("/pypi-files/")
            && let Some(body) = fixture.pypi_wheels.get(filename)
        {
            return binary_response("application/octet-stream", body.clone());
        }
        if path == format!("/os/v-/{CARGO_PACKAGE}") {
            let lines = ["1.0.0", "1.0.1"].into_iter().map(|version| {
                let filename = format!("{CARGO_PACKAGE}-{version}.crate");
                let checksum = sha256_hex(fixture.cargo_crates.get(&filename).unwrap());
                format!("{{\"name\":\"{CARGO_PACKAGE}\",\"vers\":\"{version}\",\"deps\":[],\"cksum\":\"{checksum}\",\"features\":{{}},\"yanked\":false,\"pubtime\":\"2026-06-01T00:00:00Z\"}}")
            }).collect::<Vec<_>>().join("\n");
            return RegistryResponse {
                status: 200,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                body: format!("{lines}\n").into_bytes(),
            };
        }
        if let Some(filename) = path.strip_prefix(&format!("/cargo-files/{CARGO_PACKAGE}/"))
            && let Some(body) = fixture.cargo_crates.get(filename)
        {
            return binary_response("application/octet-stream", body.clone());
        }
    }

    RegistryResponse::json(
        404,
        &json!({
            "message": format!("fixture route not found: {} {}", request.method, request.path)
        }),
    )
    .unwrap()
}

fn npm_version_metadata(base_url: &str, version: &str) -> serde_json::Value {
    json!({
        "name": NPM_PACKAGE,
        "version": version,
        "dist": {
            "tarball": format!("{base_url}/npm-files/{NPM_PACKAGE}-{version}.tgz")
        }
    })
}

fn pypi_file_metadata(base_url: &str, version: &str) -> serde_json::Value {
    let filename = format!("{PYPI_MODULE}-{version}-py3-none-any.whl");
    json!({
        "filename": filename,
        "url": format!("{base_url}/pypi-files/{filename}"),
        "hashes": {},
        "upload-time": "2026-06-01T00:00:00Z"
    })
}

fn create_npm_tarballs(root: &Path) -> HashMap<String, Vec<u8>> {
    let output_dir = root.join("npm-tarballs");
    fs::create_dir_all(&output_dir).unwrap();
    let package_dir = root.join("npm-package");
    fs::create_dir_all(&package_dir).unwrap();
    write_file(&package_dir.join("index.js"), "module.exports = 'ok';\n");

    let mut tarballs = HashMap::new();
    for version in ["1.0.0", "1.0.1"] {
        write_file(
            &package_dir.join("package.json"),
            &format!(
                r#"{{
  "name": "{NPM_PACKAGE}",
  "version": "{version}",
  "main": "index.js"
}}"#
            ),
        );
        let output = Command::new("npm")
            .arg("pack")
            .arg("--pack-destination")
            .arg(&output_dir)
            .arg("--cache")
            .arg(root.join("npm-pack-cache"))
            .current_dir(&package_dir)
            .output()
            .unwrap();
        assert_success("npm pack fixture", &output);
        let filename = format!("{NPM_PACKAGE}-{version}.tgz");
        tarballs.insert(
            filename.clone(),
            fs::read(output_dir.join(filename)).unwrap(),
        );
    }
    tarballs
}

fn create_pypi_wheels(root: &Path) -> HashMap<String, Vec<u8>> {
    let output_dir = root.join("pypi-wheels");
    fs::create_dir_all(&output_dir).unwrap();
    let mut wheels = HashMap::new();

    for version in ["1.0.0", "1.0.1"] {
        let staging = root.join(format!("pypi-wheel-{version}"));
        let package_dir = staging.join(PYPI_MODULE);
        let dist_info = staging.join(format!("{PYPI_MODULE}-{version}.dist-info"));
        fs::create_dir_all(&package_dir).unwrap();
        fs::create_dir_all(&dist_info).unwrap();
        write_file(
            &package_dir.join("__init__.py"),
            &format!("__version__ = '{version}'\n"),
        );
        write_file(
            &dist_info.join("METADATA"),
            &format!("Metadata-Version: 2.1\nName: {PYPI_PACKAGE}\nVersion: {version}\n"),
        );
        write_file(
            &dist_info.join("WHEEL"),
            "Wheel-Version: 1.0\nGenerator: osv-proxy test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        );
        write_file(
            &dist_info.join("RECORD"),
            &format!(
                "{PYPI_MODULE}/__init__.py,,\n{PYPI_MODULE}-{version}.dist-info/METADATA,,\n{PYPI_MODULE}-{version}.dist-info/WHEEL,,\n{PYPI_MODULE}-{version}.dist-info/RECORD,,\n"
            ),
        );

        let filename = format!("{PYPI_MODULE}-{version}-py3-none-any.whl");
        let wheel_path = output_dir.join(&filename);
        let output = Command::new("zip")
            .arg("-qr")
            .arg(&wheel_path)
            .arg(".")
            .current_dir(&staging)
            .output()
            .unwrap();
        assert_success("zip pypi wheel fixture", &output);
        wheels.insert(filename, fs::read(wheel_path).unwrap());
    }

    wheels
}

fn create_cargo_crates(root: &Path) -> HashMap<String, Vec<u8>> {
    let package_dir = root.join("cargo-package");
    fs::create_dir_all(package_dir.join("src")).unwrap();
    write_file(
        &package_dir.join("src/lib.rs"),
        "pub fn fixture() -> &'static str { \"ok\" }\n",
    );
    let mut crates = HashMap::new();
    for version in ["1.0.0", "1.0.1"] {
        write_file(
            &package_dir.join("Cargo.toml"),
            &format!(
                "[package]\nname = \"{CARGO_PACKAGE}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
            ),
        );
        let output = Command::new("cargo")
            .args(["package", "--allow-dirty", "--no-verify"])
            .current_dir(&package_dir)
            .output()
            .unwrap();
        assert_success("cargo package fixture", &output);
        let filename = format!("{CARGO_PACKAGE}-{version}.crate");
        crates.insert(
            filename.clone(),
            fs::read(package_dir.join("target/package").join(filename)).unwrap(),
        );
    }
    crates
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut child = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn cargo_project(path: &Path, version: &str) {
    write_file(
        &path.join("Cargo.toml"),
        &format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{CARGO_PACKAGE} = \"={version}\"\n"
        ),
    );
    write_file(&path.join("src/main.rs"), "fn main() {}\n");
}

fn write_cargo_source_replacement(path: &Path, proxy_url: &str) {
    write_cargo_source_replacement_url(path, &format!("sparse+{proxy_url}/cargo/"));
}

fn write_cargo_source_replacement_url(path: &Path, registry_url: &str) {
    write_file(
        &path.join(".cargo/config.toml"),
        &format!(
            "[source.crates-io]\nreplace-with = \"osv-proxy\"\n\n[source.osv-proxy]\nregistry = \"{registry_url}\"\n"
        ),
    );
}

type Handler = dyn Fn(HttpRequest) -> RegistryResponse + Send + Sync + 'static;

struct TestServer {
    base_url: String,
}

impl TestServer {
    fn base_url(&self) -> String {
        self.base_url.clone()
    }
}

fn start_http_server<F>(build_handler: F) -> TestServer
where
    F: FnOnce(String) -> Arc<Handler>,
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let handler = build_handler(base_url.clone());
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let handler = Arc::clone(&handler);
                    thread::spawn(move || handle_connection(stream, handler));
                }
                Err(_) => break,
            }
        }
    });
    TestServer { base_url }
}

fn handle_connection(mut stream: TcpStream, handler: Arc<Handler>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(err) => {
            let _ = write!(
                stream,
                "HTTP/1.1 400 Bad Request\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                err.len(),
                err
            );
            return;
        }
    };
    let response = handler(request);
    write_response(&mut stream, response).unwrap();
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];
    let header_end = loop {
        let bytes_read = stream.read(&mut temp).map_err(|err| err.to_string())?;
        if bytes_read == 0 {
            return Err("empty request".to_string());
        }
        buffer.extend_from_slice(&temp[..bytes_read]);
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
    };

    let header_text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = header_text.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| "missing path".to_string())?
        .to_string();
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect::<Vec<_>>();
    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let bytes_read = stream.read(&mut temp).map_err(|err| err.to_string())?;
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..bytes_read]);
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body: buffer[body_start..body_start + content_length].to_vec(),
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_response(stream: &mut TcpStream, response: RegistryResponse) -> std::io::Result<()> {
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
    stream.write_all(&response.body)
}

fn binary_response(content_type: &str, body: Vec<u8>) -> RegistryResponse {
    RegistryResponse {
        status: 200,
        headers: vec![("content-type".to_string(), content_type.to_string())],
        body,
    }
}

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("osv-proxy-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn child(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn require_command(name: &str) {
    let output = Command::new(name).arg("--version").output();
    assert!(
        output.is_ok(),
        "{name} must be installed for package-manager e2e tests"
    );
}

fn assert_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(label: &str, output: &Output) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
