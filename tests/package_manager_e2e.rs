use osv_proxy::artifact::Ecosystem;
use osv_proxy::config::{BlocklistEntry, Config};
use osv_proxy::response::RegistryResponse;
use osv_proxy::server;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zip::{ZipWriter, write::SimpleFileOptions};

const NPM_PACKAGE: &str = "osv-proxy-e2e-npm";
const PYPI_PACKAGE: &str = "osv-proxy-e2e-pypi";
const PYPI_MODULE: &str = "osv_proxy_e2e_pypi";
const NUGET_ROOT: &str = "Fixture.Root";

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

#[test]
fn dotnet_restore_uses_redirecting_nuget_proxy_with_dependency() {
    require_command("dotnet");
    let workspace = TempWorkspace::new("dotnet-restore-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));
    let mut config = Config::default();
    config.upstreams.nuget.service_index_url = format!("{}/v3/index.json", upstream.base_url());
    config.policy.osv.block_malicious = false;
    config.policy.minimum_age = Duration::from_secs(0);
    let proxy = start_axum_proxy(config);
    let project = workspace.child("project");
    fs::create_dir_all(&project).unwrap();
    write_file(
        &project.join("project.csproj"),
        &format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include=\"{NUGET_ROOT}\" Version=\"1.0.0\" /></ItemGroup></Project>"
        ),
    );
    write_file(
        &project.join("NuGet.Config"),
        &format!(
            "<configuration><packageSources><clear /><add key=\"proxy\" value=\"{}/nuget/v3/index.json\" /></packageSources></configuration>",
            proxy.base_url()
        ),
    );
    let output = Command::new("dotnet")
        .args([
            "restore",
            "--configfile",
            "NuGet.Config",
            "--packages",
            workspace.child("packages").to_str().unwrap(),
        ])
        .current_dir(&project)
        .output()
        .unwrap();
    assert_success("dotnet restore through NuGet proxy", &output);
    assert!(workspace.child("packages/fixture.root/1.0.0").exists());
    assert!(
        workspace
            .child("packages/fixture.dependency/1.0.0")
            .exists()
    );
}

#[test]
fn dotnet_restore_uses_proxying_nuget_proxy_with_dependency() {
    require_command("dotnet");
    let workspace = TempWorkspace::new("dotnet-restore-proxy-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));
    let mut config = Config::default();
    config.upstreams.nuget.service_index_url = format!("{}/v3/index.json", upstream.base_url());
    config.policy.osv.block_malicious = false;
    config.policy.minimum_age = Duration::from_secs(0);
    config.artifacts.behavior = osv_proxy::config::ArtifactBehavior::Proxy;
    let proxy = start_axum_proxy(config);
    let project = workspace.child("project");
    fs::create_dir_all(&project).unwrap();
    write_file(
        &project.join("project.csproj"),
        &format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include=\"{NUGET_ROOT}\" Version=\"1.0.0\" /></ItemGroup></Project>"
        ),
    );
    write_file(
        &project.join("NuGet.Config"),
        &format!(
            "<configuration><packageSources><clear /><add key=\"proxy\" value=\"{}/nuget/v3/index.json\" /></packageSources></configuration>",
            proxy.base_url()
        ),
    );
    let output = Command::new("dotnet")
        .args([
            "restore",
            "--configfile",
            "NuGet.Config",
            "--packages",
            workspace.child("packages").to_str().unwrap(),
        ])
        .current_dir(&project)
        .output()
        .unwrap();
    assert_success("dotnet restore through streaming NuGet proxy", &output);
    assert!(workspace.child("packages/fixture.root/1.0.0").exists());
    assert!(
        workspace
            .child("packages/fixture.dependency/1.0.0")
            .exists()
    );
}

#[test]
fn dotnet_restore_cannot_use_blocked_nuget_package() {
    require_command("dotnet");
    let workspace = TempWorkspace::new("dotnet-restore-blocked-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));
    let mut config = Config::default();
    config.upstreams.nuget.service_index_url = format!("{}/v3/index.json", upstream.base_url());
    config.policy.osv.block_malicious = false;
    config.policy.minimum_age = Duration::from_secs(0);
    config.blocklist.push(BlocklistEntry {
        ecosystem: Ecosystem::Nuget,
        name: NUGET_ROOT.into(),
        versions: vec!["1.0.0".into()],
        reason: "fixture block".into(),
    });
    let proxy = start_axum_proxy(config);
    let project = workspace.child("project");
    fs::create_dir_all(&project).unwrap();
    write_file(
        &project.join("project.csproj"),
        &format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include=\"{NUGET_ROOT}\" Version=\"1.0.0\" /></ItemGroup></Project>"
        ),
    );
    write_file(
        &project.join("NuGet.Config"),
        &format!(
            "<configuration><packageSources><clear /><add key=\"proxy\" value=\"{}/nuget/v3/index.json\" /></packageSources></configuration>",
            proxy.base_url()
        ),
    );
    let output = Command::new("dotnet")
        .args([
            "restore",
            "--configfile",
            "NuGet.Config",
            "--packages",
            workspace.child("packages").to_str().unwrap(),
        ])
        .current_dir(&project)
        .output()
        .unwrap();
    assert_failure("dotnet restore blocked package", &output);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("nuget.org"));
}

#[test]
fn locked_dotnet_restore_fails_after_nuget_package_is_blocked() {
    require_command("dotnet");
    let workspace = TempWorkspace::new("dotnet-locked-blocked-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));
    let mut allowed = Config::default();
    allowed.upstreams.nuget.service_index_url = format!("{}/v3/index.json", upstream.base_url());
    allowed.policy.osv.block_malicious = false;
    allowed.policy.minimum_age = Duration::from_secs(0);
    let allowed_proxy = start_axum_proxy(allowed);
    let project = workspace.child("project");
    fs::create_dir_all(&project).unwrap();
    write_file(
        &project.join("project.csproj"),
        &format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup><ItemGroup><PackageReference Include=\"{NUGET_ROOT}\" Version=\"1.0.0\" /></ItemGroup></Project>"
        ),
    );
    write_file(
        &project.join("NuGet.Config"),
        &format!(
            "<configuration><packageSources><clear/><add key=\"proxy\" value=\"{}/nuget/v3/index.json\"/></packageSources></configuration>",
            allowed_proxy.base_url()
        ),
    );
    let first = Command::new("dotnet")
        .args([
            "restore",
            "--configfile",
            "NuGet.Config",
            "--packages",
            workspace.child("allowed-packages").to_str().unwrap(),
        ])
        .current_dir(&project)
        .output()
        .unwrap();
    assert_success("allowed locked restore", &first);
    assert!(project.join("packages.lock.json").exists());
    let mut blocked = Config::default();
    blocked.upstreams.nuget.service_index_url = format!("{}/v3/index.json", upstream.base_url());
    blocked.policy.osv.block_malicious = false;
    blocked.policy.minimum_age = Duration::from_secs(0);
    blocked.blocklist.push(BlocklistEntry {
        ecosystem: Ecosystem::Nuget,
        name: NUGET_ROOT.into(),
        versions: vec!["1.0.0".into()],
        reason: "locked fixture block".into(),
    });
    let blocked_proxy = start_axum_proxy(blocked);
    write_file(
        &project.join("NuGet.Config"),
        &format!(
            "<configuration><packageSources><clear/><add key=\"proxy\" value=\"{}/nuget/v3/index.json\"/></packageSources></configuration>",
            blocked_proxy.base_url()
        ),
    );
    let second = Command::new("dotnet")
        .args([
            "restore",
            "--locked-mode",
            "--configfile",
            "NuGet.Config",
            "--packages",
            workspace.child("blocked-packages").to_str().unwrap(),
        ])
        .current_dir(&project)
        .output()
        .unwrap();
    assert_failure("locked restore newly blocked package", &second);
    assert!(!String::from_utf8_lossy(&second.stderr).contains("nuget.org"));
}

struct FixtureArtifacts {
    npm_tarballs: HashMap<String, Vec<u8>>,
    pypi_wheels: HashMap<String, Vec<u8>>,
    nuget_packages: HashMap<String, Vec<u8>>,
}

impl FixtureArtifacts {
    fn create(root: &Path) -> Self {
        Self {
            npm_tarballs: create_npm_tarballs(root),
            pypi_wheels: create_pypi_wheels(root),
            nuget_packages: create_nuget_packages(),
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
            config.policy.osv.api_url = upstream_base_url.clone();
            config.blocklist.push(BlocklistEntry {
                ecosystem: Ecosystem::Npm,
                name: NPM_PACKAGE.to_string(),
                versions: vec!["1.0.1".to_string()],
                reason: "package-manager e2e blocked npm version".to_string(),
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

/// Starts the real Axum listener used by client compatibility tests. Unlike the
/// synchronous route helper above this exercises the production HTTP path.
fn start_axum_proxy(mut config: Config) -> TestServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    config.server.bind = listener.local_addr().unwrap().to_string();
    config.server.public_base_url = base_url.clone();
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, server::router(config)).await.unwrap();
        });
    });
    TestServer { base_url }
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
    if request.method == "GET" && path == "/v3/index.json" {
        return RegistryResponse::json(200, &json!({"version":"3.0.0","resources":[{"@id":format!("{base_url}/registration/"),"@type":"RegistrationsBaseUrl/3.6.0"},{"@id":format!("{base_url}/flat/"),"@type":"PackageBaseAddress/3.0.0"}]})).unwrap();
    }
    if request.method == "GET" && path.starts_with("/registration/") {
        let id = path
            .trim_start_matches("/registration/")
            .trim_end_matches("/index.json");
        let (version, dependency) = if id == "fixture.root" {
            ("1.0.0", Some("Fixture.Dependency"))
        } else {
            ("1.0.0", None)
        };
        return RegistryResponse::json(200, &json!({"items":[{"count":1,"items":[{"catalogEntry":{"version":version,"published":"2020-01-01T00:00:00Z","dependencyGroups":dependency.map(|name| json!([{ "dependencies":[{"id":name,"range":"[1.0.0]"}]}])).unwrap_or(json!([]))},"packageContent":format!("{base_url}/packages/{id}.{version}.nupkg")}]}]})).unwrap();
    }
    if request.method == "GET" && path.starts_with("/flat/") && path.ends_with("/index.json") {
        return RegistryResponse::json(200, &json!({"versions":["1.0.0"]})).unwrap();
    }
    if request.method == "GET" && path.starts_with("/packages/") {
        let name = path.trim_start_matches("/packages/");
        if let Some(bytes) = fixture.nuget_packages.get(name) {
            return binary_response("application/octet-stream", bytes.clone());
        }
    }

    if request.method == "GET" {
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

fn create_nuget_packages() -> HashMap<String, Vec<u8>> {
    [
        ("fixture.root", "Fixture.Root", Some("Fixture.Dependency")),
        ("fixture.dependency", "Fixture.Dependency", None),
    ].into_iter().map(|(key, id, dependency)| {
        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer.start_file(format!("{id}.nuspec"), SimpleFileOptions::default()).unwrap();
        let dependencies = dependency.map(|dep| format!("<dependencies><dependency id=\"{dep}\" version=\"[1.0.0]\" /></dependencies>")).unwrap_or_default();
        writer.write_all(format!("<?xml version=\"1.0\"?><package><metadata><id>{id}</id><version>1.0.0</version><authors>test</authors><description>fixture</description>{dependencies}</metadata></package>").as_bytes()).unwrap();
        (format!("{key}.1.0.0.nupkg"), writer.finish().unwrap().into_inner())
    }).collect()
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
