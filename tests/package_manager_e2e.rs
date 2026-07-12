use osv_proxy::artifact::Ecosystem;
use osv_proxy::config::{AllowlistEntry, ArtifactBehavior, Config, OsvSource};
use osv_proxy::response::RegistryResponse;
use osv_proxy::server;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

const NPM_PACKAGE: &str = "osv-proxy-e2e-npm";
const PYPI_PACKAGE: &str = "osv-proxy-e2e-pypi";
const PYPI_MODULE: &str = "osv_proxy_e2e_pypi";
const GO_MODULE: &str = "example.com/fixture";
const NUGET_ROOT: &str = "Fixture.Root";
const RUBYGEMS_ROOT: &str = "osv-proxy-e2e-ruby";
const RUBYGEMS_DEPENDENCY: &str = "osv-proxy-e2e-ruby-dependency";
const RUBYGEMS_PLATFORM: &str = "osv-proxy-e2e-ruby-platform";
const RUBYGEMS_PRERELEASE: &str = "osv-proxy-e2e-ruby-prerelease";
const MAVEN_GROUP: &str = "com.acme";
const MAVEN_ROOT: &str = "osv-proxy-e2e-maven";
const MAVEN_BOM: &str = "osv-proxy-e2e-maven-bom";
const MAVEN_DEPENDENCY: &str = "osv-proxy-e2e-maven-dependency";
const MAVEN_GRADLE_DEPENDENCY: &str = "osv-proxy-e2e-gradle-dependency";

#[test]
fn maven_resolves_redirect_proxy_dynamic_and_pinned_denials() {
    require_command("java");
    require_command("mvn");
    let workspace = TempWorkspace::new("maven-resolver-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));

    for behavior in [ArtifactBehavior::Redirect, ArtifactBehavior::Proxy] {
        let proxy = start_axum_proxy(maven_e2e_config(&upstream, behavior, true));
        let project = workspace.child(match behavior {
            ArtifactBehavior::Redirect => "maven-redirect",
            _ => "maven-proxy",
        });
        write_maven_extension_project(&project, &proxy, "1.0.0");
        let repository = workspace.child(match behavior {
            ArtifactBehavior::Redirect => "maven-repository-redirect",
            _ => "maven-repository-proxy",
        });
        let output = run_maven_validate(&project, &repository);
        assert_success("Maven extension/transitive resolution", &output);
        assert!(maven_cached(&repository, MAVEN_ROOT, "1.0.0", "jar"));
        assert!(maven_cached(&repository, MAVEN_DEPENDENCY, "1.0.0", "jar"));
        assert!(maven_cached(&repository, MAVEN_BOM, "1.0.0", "pom"));
    }

    let filtered_proxy = start_axum_proxy(maven_e2e_config(
        &upstream,
        ArtifactBehavior::Redirect,
        true,
    ));
    let dynamic = workspace.child("maven-dynamic-filtered");
    write_maven_extension_project(&dynamic, &filtered_proxy, "[1.0,2.0)");
    let dynamic_repository = workspace.child("maven-dynamic-repository");
    let dynamic_output = run_maven_validate(&dynamic, &dynamic_repository);
    assert_success(
        "Maven dynamic version selects allowed release",
        &dynamic_output,
    );
    assert!(maven_cached(
        &dynamic_repository,
        MAVEN_ROOT,
        "1.0.0",
        "jar"
    ));
    assert!(!maven_cached(
        &dynamic_repository,
        MAVEN_ROOT,
        "1.0.1",
        "jar"
    ));

    let blocked = workspace.child("maven-blocked-fresh");
    write_maven_extension_project(&blocked, &filtered_proxy, "1.0.1");
    let blocked_output = run_maven_validate(&blocked, &workspace.child("maven-blocked-cache"));
    assert_maven_or_gradle_denial("fresh blocked Maven resolution", &blocked_output);

    let blocked_bom = workspace.child("maven-blocked-bom");
    write_maven_bom_project(&blocked_bom, &filtered_proxy, "1.0.1");
    let blocked_bom_output =
        run_maven_validate(&blocked_bom, &workspace.child("maven-blocked-bom-cache"));
    assert_maven_denial_for(
        "fresh blocked Maven BOM import",
        &blocked_bom_output,
        MAVEN_BOM,
    );

    let seed_proxy = start_axum_proxy(maven_e2e_config(
        &upstream,
        ArtifactBehavior::Redirect,
        false,
    ));
    let pinned = workspace.child("maven-pinned-transition");
    write_maven_extension_project(&pinned, &seed_proxy, "1.0.1");
    assert_success(
        "seed pinned Maven coordinate",
        &run_maven_validate(&pinned, &workspace.child("maven-pinned-seed-cache")),
    );
    replace_file_text(
        &pinned.join("settings.xml"),
        &seed_proxy.base_url(),
        &filtered_proxy.base_url(),
    );
    let pinned_output = run_maven_validate(&pinned, &workspace.child("maven-pinned-blocked-cache"));
    assert_maven_or_gradle_denial("pinned blocked Maven resolution", &pinned_output);
}

#[test]
fn gradle_resolves_module_metadata_redirect_proxy_and_lock_denials() {
    require_command("java");
    require_command("gradle");
    let workspace = TempWorkspace::new("gradle-resolver-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));

    for behavior in [ArtifactBehavior::Redirect, ArtifactBehavior::Proxy] {
        let proxy = start_axum_proxy(maven_e2e_config(&upstream, behavior, true));
        let project = workspace.child(match behavior {
            ArtifactBehavior::Redirect => "gradle-redirect",
            _ => "gradle-proxy",
        });
        write_gradle_project(&project, &proxy, "[1.0,2.0)");
        let output = run_gradle_copy(
            &project,
            workspace.child(match behavior {
                ArtifactBehavior::Redirect => "gradle-home-redirect",
                _ => "gradle-home-proxy",
            }),
            false,
        );
        assert_success("Gradle module-metadata resolution", &output);
        assert!(
            project
                .join(format!("resolved/{MAVEN_ROOT}-1.0.0.jar"))
                .exists()
        );
        assert!(
            project
                .join(format!("resolved/{MAVEN_GRADLE_DEPENDENCY}-1.0.0.jar"))
                .exists(),
            "Gradle did not use the .module dependency graph"
        );
        assert!(
            !project
                .join(format!("resolved/{MAVEN_DEPENDENCY}-1.0.0.jar"))
                .exists(),
            "Gradle unexpectedly used the POM dependency graph"
        );
    }

    let blocked_proxy = start_axum_proxy(maven_e2e_config(
        &upstream,
        ArtifactBehavior::Redirect,
        true,
    ));
    let blocked = workspace.child("gradle-blocked-fresh");
    write_gradle_project(&blocked, &blocked_proxy, "1.0.1");
    let blocked_output = run_gradle_copy(&blocked, workspace.child("gradle-blocked-home"), false);
    assert_maven_or_gradle_denial("fresh blocked Gradle resolution", &blocked_output);

    let seed_proxy = start_axum_proxy(maven_e2e_config(
        &upstream,
        ArtifactBehavior::Redirect,
        false,
    ));
    let locked = workspace.child("gradle-locked-transition");
    write_gradle_project(&locked, &seed_proxy, "1.0.1");
    assert_success(
        "seed Gradle lockfile",
        &run_gradle_copy(&locked, workspace.child("gradle-lock-seed-home"), true),
    );
    replace_file_text(
        &locked.join("build.gradle"),
        &seed_proxy.base_url(),
        &blocked_proxy.base_url(),
    );
    let _ = fs::remove_dir_all(locked.join("resolved"));
    let locked_output =
        run_gradle_copy(&locked, workspace.child("gradle-lock-blocked-home"), false);
    assert_maven_or_gradle_denial("locked blocked Gradle resolution", &locked_output);
}

fn maven_e2e_config(
    upstream: &TestServer,
    behavior: ArtifactBehavior,
    enforce_vulnerability_policy: bool,
) -> Config {
    let mut config = Config::default();
    config.upstreams.maven.repository_url = upstream.base_url();
    config.policy.osv.api_url = upstream.base_url();
    config.policy.osv.source = OsvSource::Live;
    config.policy.minimum_age = Duration::ZERO;
    config.artifacts.behavior = behavior;
    if !enforce_vulnerability_policy {
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
    }
    config
}

fn write_maven_extension_project(project: &Path, proxy: &TestServer, version: &str) {
    fs::create_dir_all(project.join(".mvn")).unwrap();
    write_file(
        &project.join("pom.xml"),
        &format!(
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><modelVersion>4.0.0</modelVersion><groupId>client</groupId><artifactId>client</artifactId><version>1.0.0</version><dependencyManagement><dependencies><dependency><groupId>{MAVEN_GROUP}</groupId><artifactId>{MAVEN_BOM}</artifactId><version>1.0.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement><dependencies><dependency><groupId>{MAVEN_GROUP}</groupId><artifactId>{MAVEN_DEPENDENCY}</artifactId></dependency></dependencies></project>"
        ),
    );
    write_file(
        &project.join(".mvn/extensions.xml"),
        &format!(
            "<extensions><extension><groupId>{MAVEN_GROUP}</groupId><artifactId>{MAVEN_ROOT}</artifactId><version>{version}</version></extension></extensions>"
        ),
    );
    write_file(
        &project.join("settings.xml"),
        &format!(
            "<settings xmlns=\"http://maven.apache.org/SETTINGS/1.2.0\"><mirrors><mirror><id>osv-proxy</id><url>{}/maven/</url><mirrorOf>*</mirrorOf></mirror></mirrors></settings>",
            proxy.base_url()
        ),
    );
}

fn write_maven_bom_project(project: &Path, proxy: &TestServer, version: &str) {
    fs::create_dir_all(project).unwrap();
    write_file(
        &project.join("pom.xml"),
        &format!(
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><modelVersion>4.0.0</modelVersion><groupId>client</groupId><artifactId>blocked-bom-client</artifactId><version>1.0.0</version><dependencyManagement><dependencies><dependency><groupId>{MAVEN_GROUP}</groupId><artifactId>{MAVEN_BOM}</artifactId><version>{version}</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>"
        ),
    );
    write_file(
        &project.join("settings.xml"),
        &format!(
            "<settings xmlns=\"http://maven.apache.org/SETTINGS/1.2.0\"><mirrors><mirror><id>osv-proxy</id><url>{}/maven/</url><mirrorOf>*</mirrorOf></mirror></mirrors></settings>",
            proxy.base_url()
        ),
    );
}

fn run_maven_validate(project: &Path, repository: &Path) -> Output {
    fs::create_dir_all(repository).unwrap();
    Command::new("mvn")
        .args(["--batch-mode", "--errors", "--settings", "settings.xml"])
        .arg(format!("-Dmaven.repo.local={}", repository.display()))
        .arg("validate")
        .current_dir(project)
        .env("MAVEN_OPTS", "-Dmaven.wagon.http.retryHandler.count=0")
        .output()
        .unwrap()
}

fn maven_cached(repository: &Path, artifact: &str, version: &str, extension: &str) -> bool {
    repository
        .join(MAVEN_GROUP.replace('.', "/"))
        .join(artifact)
        .join(version)
        .join(format!("{artifact}-{version}.{extension}"))
        .exists()
}

fn write_gradle_project(project: &Path, proxy: &TestServer, version: &str) {
    fs::create_dir_all(project).unwrap();
    write_file(
        &project.join("settings.gradle"),
        "rootProject.name = 'client'\n",
    );
    write_file(
        &project.join("build.gradle"),
        &format!(
            "repositories {{ maven {{ url = uri('{}/maven/') }} }}\nconfigurations {{ runtimeClasspath }}\ndependencies {{ runtimeClasspath '{MAVEN_GROUP}:{MAVEN_ROOT}:{version}' }}\ndependencyLocking {{ lockAllConfigurations() }}\ntasks.register('copyDeps', Copy) {{ from configurations.runtimeClasspath; into layout.projectDirectory.dir('resolved') }}\n",
            proxy.base_url()
        ),
    );
}

fn run_gradle_copy(project: &Path, gradle_home: PathBuf, write_locks: bool) -> Output {
    fs::create_dir_all(&gradle_home).unwrap();
    let mut command = Command::new("gradle");
    command.args([
        "--no-daemon",
        "--stacktrace",
        "--refresh-dependencies",
        "--gradle-user-home",
    ]);
    command.arg(gradle_home);
    if write_locks {
        command.arg("--write-locks");
    }
    command
        .arg("copyDeps")
        .current_dir(project)
        .output()
        .unwrap()
}

fn assert_maven_or_gradle_denial(context: &str, output: &Output) {
    assert_maven_denial_for(context, output, MAVEN_ROOT);
}

fn assert_maven_denial_for(context: &str, output: &Output, artifact: &str) {
    assert_failure(context, output);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(artifact),
        "{context} did not fail on the protected coordinate: {combined}"
    );
    assert!(
        !combined.contains("repo.maven.apache.org") && !combined.contains("services.gradle.org"),
        "{context} attempted public repository fallback: {combined}"
    );
}

#[test]
fn bundler_install_uses_proxy_for_resolution_delivery_and_denials() {
    require_command("ruby");
    require_command("gem");
    require_command("bundle");
    let workspace = TempWorkspace::new("bundler-install-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create_with_rubygems(workspace.path()));

    for behavior in [ArtifactBehavior::Redirect, ArtifactBehavior::Proxy] {
        let proxy = start_axum_proxy(rubygems_e2e_config(
            &upstream,
            behavior,
            false,
            RUBYGEMS_ROOT,
            "1.0.0",
        ));
        let project = workspace.child(match behavior {
            ArtifactBehavior::Redirect => "ruby-redirect",
            _ => "ruby-proxy",
        });
        write_gemfile(
            &project,
            &proxy,
            &[(RUBYGEMS_ROOT, "1.0.0"), (RUBYGEMS_PLATFORM, "1.0.0")],
        );
        let cache = workspace.child(match behavior {
            ArtifactBehavior::Redirect => "ruby-install-cache-redirect",
            _ => "ruby-install-cache-proxy",
        });
        let output = run_bundle_install(&project, cache, false);
        assert_success("Bundler dependency/platform install", &output);
        let lock = fs::read_to_string(project.join("Gemfile.lock")).unwrap();
        assert!(lock.contains(RUBYGEMS_DEPENDENCY));
        assert!(lock.contains(RUBYGEMS_PLATFORM));
    }

    let prerelease_proxy = start_axum_proxy(rubygems_e2e_config(
        &upstream,
        ArtifactBehavior::Redirect,
        false,
        RUBYGEMS_PRERELEASE,
        "1.1.0.pre.1",
    ));
    let prerelease = workspace.child("ruby-prerelease");
    write_gemfile(
        &prerelease,
        &prerelease_proxy,
        &[(RUBYGEMS_PRERELEASE, "1.1.0.pre.1")],
    );
    assert_success(
        "Bundler prerelease install",
        &run_bundle_install(&prerelease, workspace.child("ruby-prerelease-cache"), false),
    );

    let blocked_proxy = start_axum_proxy(rubygems_e2e_config(
        &upstream,
        ArtifactBehavior::Redirect,
        true,
        RUBYGEMS_ROOT,
        "1.0.1",
    ));
    let fresh = workspace.child("ruby-blocked-fresh");
    write_gemfile(&fresh, &blocked_proxy, &[(RUBYGEMS_ROOT, "1.0.1")]);
    assert_bundler_denial(
        "fresh blocked Bundler install",
        &run_bundle_install(&fresh, workspace.child("ruby-blocked-fresh-cache"), false),
    );

    let allowed_proxy = start_axum_proxy(rubygems_e2e_config(
        &upstream,
        ArtifactBehavior::Redirect,
        false,
        RUBYGEMS_ROOT,
        "1.0.1",
    ));
    let locked = workspace.child("ruby-blocked-locked");
    write_gemfile(&locked, &allowed_proxy, &[(RUBYGEMS_ROOT, "1.0.1")]);
    assert_success(
        "seed Bundler lockfile",
        &run_bundle_install(&locked, workspace.child("ruby-lock-seed-cache"), false),
    );
    replace_file_text(
        &locked.join("Gemfile"),
        &allowed_proxy.base_url(),
        &blocked_proxy.base_url(),
    );
    replace_file_text(
        &locked.join("Gemfile.lock"),
        &allowed_proxy.base_url(),
        &blocked_proxy.base_url(),
    );
    assert_bundler_denial(
        "locked blocked Bundler install",
        &run_bundle_install(&locked, workspace.child("ruby-blocked-lock-cache"), true),
    );
}

fn rubygems_e2e_config(
    upstream: &TestServer,
    behavior: ArtifactBehavior,
    block: bool,
    package: &str,
    version: &str,
) -> Config {
    let mut config = Config::default();
    config.upstreams.rubygems.registry_url = upstream.base_url();
    config.policy.osv.api_url = upstream.base_url();
    config.policy.osv.source = OsvSource::Live;
    config.policy.minimum_age = Duration::from_secs(0);
    config.artifacts.behavior = behavior;
    if !block {
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::RubyGems,
            name: package.into(),
            version: version.into(),
            bypass_age_gate: false,
            bypass_osv: true,
            reason: "exercise allowed Bundler path separately".into(),
        });
        config.policy.osv.block_malicious = false;
        config.policy.osv.block_vulnerabilities = false;
    }
    config
}

fn write_gemfile(project: &Path, proxy: &TestServer, gems: &[(&str, &str)]) {
    fs::create_dir_all(project).unwrap();
    let mut body = format!("source \"{}/rubygems/\"\n", proxy.base_url());
    for (name, version) in gems {
        body.push_str(&format!("gem \"{name}\", \"= {version}\"\n"));
    }
    write_file(&project.join("Gemfile"), &body);
}

fn run_bundle_install(project: &Path, cache: PathBuf, locked: bool) -> Output {
    let home = project.join("home");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&cache).unwrap();
    let mut command = Command::new("bundle");
    command.args(["install", "--jobs", "1", "--retry", "0", "--verbose"]);
    if locked {
        command.arg("--deployment");
    }
    command
        .current_dir(project)
        .env("HOME", &home)
        .env("BUNDLE_USER_HOME", home.join(".bundle"))
        .env("BUNDLE_PATH", cache.join("gems"))
        .env("BUNDLE_CACHE_PATH", cache.join("cache"))
        .env("BUNDLE_DISABLE_VERSION_CHECK", "true")
        .output()
        .unwrap()
}

fn assert_bundler_denial(context: &str, output: &Output) {
    assert_failure(context, output);
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("https://rubygems.org"),
        "{context} used fallback: {combined}"
    );
}

#[test]
fn dotnet_restore_uses_redirecting_nuget_proxy_with_dependency() {
    nuget_restore_case(
        "dotnet-restore-e2e",
        ArtifactBehavior::Redirect,
        NUGET_ROOT,
        "1.0.0",
        false,
        false,
    );
}
#[test]
fn dotnet_restore_uses_proxying_nuget_proxy_with_dependency() {
    nuget_restore_case(
        "dotnet-restore-proxy-e2e",
        ArtifactBehavior::Proxy,
        NUGET_ROOT,
        "1.0.0",
        false,
        false,
    );
}
#[test]
fn dotnet_restore_cannot_use_blocked_nuget_package() {
    nuget_restore_case(
        "dotnet-restore-blocked-e2e",
        ArtifactBehavior::Redirect,
        NUGET_ROOT,
        "1.0.0",
        true,
        false,
    );
}
#[test]
fn locked_dotnet_restore_fails_after_nuget_package_is_blocked() {
    nuget_restore_case(
        "dotnet-locked-blocked-e2e",
        ArtifactBehavior::Redirect,
        NUGET_ROOT,
        "1.0.0",
        true,
        true,
    );
}
#[test]
fn dotnet_restore_explicit_nuget_prerelease_through_proxy() {
    nuget_restore_case(
        "dotnet-prerelease-e2e",
        ArtifactBehavior::Redirect,
        "Fixture.Prerelease",
        "1.1.0-beta.1",
        false,
        false,
    );
}

fn nuget_restore_case(
    label: &str,
    behavior: ArtifactBehavior,
    package: &str,
    version: &str,
    blocked: bool,
    locked_transition: bool,
) {
    require_command("dotnet");
    let workspace = TempWorkspace::new(label);
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));
    let project = workspace.child("project");
    fs::create_dir_all(&project).unwrap();
    write_file(
        &project.join("project.csproj"),
        &format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0</TargetFramework>{}</PropertyGroup><ItemGroup><PackageReference Include=\"{package}\" Version=\"{version}\" /></ItemGroup></Project>",
            if locked_transition {
                "<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>"
            } else {
                ""
            }
        ),
    );
    let mut allowed = nuget_e2e_config(&upstream, behavior, false, package, version);
    let allowed_proxy = start_axum_proxy(std::mem::take(&mut allowed));
    write_nuget_proxy_config(&project, &allowed_proxy);
    let first = run_dotnet_restore(&project, workspace.child("allowed-packages"), false);
    if !blocked {
        assert_success("NuGet restore", &first);
        return;
    }
    if locked_transition {
        assert_success("seed locked NuGet restore", &first);
    }
    let blocked_proxy = start_axum_proxy(nuget_e2e_config(
        &upstream, behavior, true, package, version,
    ));
    write_nuget_proxy_config(&project, &blocked_proxy);
    let result = run_dotnet_restore(
        &project,
        workspace.child("blocked-packages"),
        locked_transition,
    );
    assert_failure("blocked NuGet restore", &result);
    assert!(!String::from_utf8_lossy(&result.stderr).contains("nuget.org"));
}

fn nuget_e2e_config(
    upstream: &TestServer,
    behavior: ArtifactBehavior,
    blocked: bool,
    package: &str,
    version: &str,
) -> Config {
    let mut config = Config::default();
    config.upstreams.nuget.service_index_url = format!("{}/v3/index.json", upstream.base_url());
    config.policy.osv.api_url = upstream.base_url();
    config.policy.osv.source = OsvSource::Live;
    config.policy.osv.block_malicious = false;
    config.policy.minimum_age = Duration::from_secs(0);
    config.artifacts.behavior = behavior;
    if !blocked && package == NUGET_ROOT {
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::Nuget,
            name: package.into(),
            version: version.into(),
            bypass_age_gate: false,
            bypass_osv: true,
            reason: "exercise allowed NuGet client path separately".into(),
        });
    }
    config
}

fn write_nuget_proxy_config(project: &Path, proxy: &TestServer) {
    write_file(
        &project.join("NuGet.Config"),
        &format!(
            "<configuration><packageSources><clear/><add key=\"proxy\" value=\"{}/nuget/v3/index.json\" allowInsecureConnections=\"true\"/></packageSources></configuration>",
            proxy.base_url()
        ),
    );
}

fn run_dotnet_restore(project: &Path, packages: PathBuf, locked: bool) -> Output {
    let dotnet_home = project.join(".dotnet-home");
    fs::create_dir_all(&dotnet_home).unwrap();
    let mut command = Command::new("dotnet");
    command.arg("restore");
    if locked {
        command.arg("--locked-mode");
    }
    command
        .args([
            "--configfile",
            "NuGet.Config",
            "--packages",
            packages.to_str().unwrap(),
        ])
        .current_dir(project)
        .env("DOTNET_CLI_HOME", dotnet_home)
        .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
        .output()
        .unwrap()
}

#[test]
fn go_mod_download_uses_hermetic_proxy() {
    require_command("go");
    let workspace = TempWorkspace::new("go-mod-download-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));
    let proxy = start_proxy(upstream.base_url());
    let project = workspace.child("go-client");
    fs::create_dir_all(&project).unwrap();
    write_file(
        &project.join("go.mod"),
        "module client.example/test\n\ngo 1.24\n\nrequire example.com/fixture v1.0.0\n",
    );
    let output = Command::new("go")
        .arg("mod")
        .arg("download")
        .arg("example.com/fixture")
        .current_dir(&project)
        .env("GOPROXY", format!("{}/go", proxy.base_url()))
        .env("GOSUMDB", "off")
        .env("GONOSUMDB", "*")
        .env("GONOPROXY", "")
        .env("GOPRIVATE", "")
        .env("GOMODCACHE", workspace.child("go-cache"))
        .output()
        .unwrap();
    assert_success("go mod download through proxy", &output);
    assert!(project.join("go.sum").exists());
}

#[test]
fn go_mod_download_denials_are_terminal_for_fresh_and_locked_state() {
    require_command("go");
    let workspace = TempWorkspace::new("go-mod-denial-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));
    let allowed = start_proxy(upstream.base_url());
    let blocked = start_go_proxy(upstream.base_url(), true, ArtifactBehavior::Redirect);
    let project = workspace.child("go-client");
    fs::create_dir_all(&project).unwrap();
    write_file(
        &project.join("go.mod"),
        "module client.example/test\n\ngo 1.24\n\nrequire example.com/fixture v1.0.0\n",
    );
    assert_success(
        "seed locked Go module",
        &go_download(&project, &allowed, workspace.child("seed-cache")),
    );
    assert!(project.join("go.sum").exists());
    let fresh = go_download(&project, &blocked, workspace.child("fresh-cache"));
    assert_policy_denial("fresh blocked Go module", &fresh);
    let locked = go_download(&project, &blocked, workspace.child("locked-cache"));
    assert_policy_denial("locked blocked Go module", &locked);
}

#[test]
fn go_mod_download_works_with_proxy_artifact_mode() {
    require_command("go");
    let workspace = TempWorkspace::new("go-mod-proxy-mode-e2e");
    let upstream = start_fixture_upstream(FixtureArtifacts::create(workspace.path()));
    let proxy = start_go_proxy(upstream.base_url(), false, ArtifactBehavior::Proxy);
    let project = workspace.child("go-client");
    fs::create_dir_all(&project).unwrap();
    write_file(
        &project.join("go.mod"),
        "module client.example/test\n\ngo 1.24\n\nrequire example.com/fixture v1.0.0\n",
    );
    assert_success(
        "Go module download in proxy artifact mode",
        &go_download(&project, &proxy, workspace.child("proxy-cache")),
    );
}
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
    nuget_packages: HashMap<String, Vec<u8>>,
    cargo_crates: HashMap<String, Vec<u8>>,
    rubygems: Vec<RubyGemFixture>,
    maven_files: HashMap<String, MavenFileFixture>,
}

struct MavenFileFixture {
    content_type: &'static str,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct RubyGemFixture {
    name: String,
    version: String,
    platform: String,
    created_at: String,
    dependencies: Vec<(String, String)>,
    bytes: Vec<u8>,
    sha256: String,
}

impl RubyGemFixture {
    fn filename(&self) -> String {
        if self.platform == "ruby" {
            format!("{}-{}.gem", self.name, self.version)
        } else {
            format!("{}-{}-{}.gem", self.name, self.version, self.platform)
        }
    }
}

impl FixtureArtifacts {
    fn create(root: &Path) -> Self {
        Self {
            npm_tarballs: create_npm_tarballs(root),
            pypi_wheels: create_pypi_wheels(root),
            nuget_packages: create_nuget_packages(),
            cargo_crates: create_cargo_crates(root),
            rubygems: Vec::new(),
            maven_files: create_maven_files(),
        }
    }

    fn create_with_rubygems(root: &Path) -> Self {
        let mut fixture = Self::create(root);
        fixture.rubygems = create_rubygems(root);
        fixture
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
    start_go_proxy(upstream_base_url, false, ArtifactBehavior::Redirect)
}

/// Starts the production Axum HTTP path for NuGet client compatibility tests.
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

fn start_proxy_with_behavior(upstream_base_url: String, behavior: ArtifactBehavior) -> TestServer {
    start_go_proxy(upstream_base_url, false, behavior)
}

fn start_go_proxy(
    upstream_base_url: String,
    block_go: bool,
    behavior: ArtifactBehavior,
) -> TestServer {
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
            config.upstreams.go.proxy_url = upstream_base_url.clone();
            config.upstreams.cargo.sparse_index_url = upstream_base_url.clone();
            config.upstreams.cargo.download_url = format!("{upstream_base_url}/cargo-files");
            config.policy.osv.api_url = upstream_base_url.clone();
            config.policy.osv.source = OsvSource::Live;
            config.artifacts.behavior = behavior;
            if !block_go {
                config.allowlist.push(AllowlistEntry {
                    ecosystem: Ecosystem::Go,
                    name: GO_MODULE.to_string(),
                    version: "v1.0.0".to_string(),
                    bypass_age_gate: false,
                    bypass_osv: true,
                    reason: "exercise allowed Go client path separately".to_string(),
                });
            }

            runtime.block_on(server::route_request_with_accept(
                &config,
                &request.method,
                &request.path,
                request.header("accept"),
            ))
        })
    })
}

fn go_download(project: &Path, proxy: &TestServer, cache: PathBuf) -> Output {
    Command::new("go")
        .arg("mod")
        .arg("download")
        .arg(GO_MODULE)
        .current_dir(project)
        .env("GOPROXY", format!("{}/go", proxy.base_url()))
        .env("GOSUMDB", "off")
        .env("GONOSUMDB", "*")
        .env("GONOPROXY", "")
        .env("GOPRIVATE", "")
        .env("GOMODCACHE", cache)
        .output()
        .unwrap()
}

fn assert_policy_denial(context: &str, output: &Output) {
    assert_failure(context, output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("403"),
        "{context} did not fail with terminal policy denial: {stderr}"
    );
    assert!(
        !stderr.contains("direct"),
        "{context} attempted direct fallback: {stderr}"
    );
}

fn fixture_response(
    fixture: &FixtureArtifacts,
    base_url: &str,
    request: HttpRequest,
) -> RegistryResponse {
    let path = request.path.split('?').next().unwrap_or(&request.path);
    if request.method == "POST" && path == "/v1/query" {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body).unwrap();
        let vulnerable = is_e2e_vulnerable_query(&body);
        return RegistryResponse::json(
            200,
            &if vulnerable {
                json!({ "vulns": [e2e_vulnerability()] })
            } else {
                json!({ "vulns": [] })
            },
        )
        .unwrap();
    }
    if request.method == "POST" && path == "/v1/querybatch" {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body).unwrap();
        let results = body["queries"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|query| {
                if is_e2e_vulnerable_query(query) {
                    json!({ "vulns": [{"id":"GHSA-e2e-vulnerable","modified":"2026-07-11T00:00:00Z"}] })
                } else {
                    json!({ "vulns": [] })
                }
            })
            .collect::<Vec<_>>();
        return RegistryResponse::json(200, &json!({ "results": results })).unwrap();
    }
    if request.method == "GET" && path == "/v1/vulns/GHSA-e2e-vulnerable" {
        return RegistryResponse::json(200, &e2e_vulnerability()).unwrap();
    }

    if matches!(request.method.as_str(), "GET" | "HEAD")
        && let Some(file) = fixture.maven_files.get(path)
    {
        let mut response = RegistryResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), file.content_type.to_string()),
                ("content-length".to_string(), file.bytes.len().to_string()),
                (
                    "last-modified".to_string(),
                    "Sun, 01 Jun 2025 00:00:00 GMT".to_string(),
                ),
                ("x-checksum-sha256".to_string(), sha256_hex(&file.bytes)),
            ],
            body: file.bytes.clone(),
        };
        if request.method == "HEAD" {
            response.body.clear();
        }
        return response;
    }

    if request.method == "GET" && path == "/versions" {
        let mut names = fixture
            .rubygems
            .iter()
            .map(|gem| gem.name.as_str())
            .collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        let mut body = "created_at: 2026-07-01T00:00:00Z\n---\n".to_string();
        for name in names {
            let info = rubygems_info(fixture, name);
            let versions = fixture
                .rubygems
                .iter()
                .filter(|gem| gem.name == name)
                .map(|gem| {
                    if gem.platform == "ruby" {
                        gem.version.clone()
                    } else {
                        format!("{}-{}", gem.version, gem.platform)
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            body.push_str(&format!(
                "{name} {versions} {:x}\n",
                md5::compute(info.as_bytes())
            ));
        }
        return text_response(body);
    }
    if request.method == "GET"
        && let Some(name) = path.strip_prefix("/info/")
        && fixture.rubygems.iter().any(|gem| gem.name == name)
    {
        return text_response(rubygems_info(fixture, name));
    }
    if request.method == "GET"
        && let Some(name) = path
            .strip_prefix("/api/v1/versions/")
            .and_then(|name| name.strip_suffix(".json"))
        && fixture.rubygems.iter().any(|gem| gem.name == name)
    {
        let versions = fixture
            .rubygems
            .iter()
            .filter(|gem| gem.name == name)
            .map(|gem| {
                json!({
                    "number": gem.version,
                    "platform": gem.platform,
                    "created_at": gem.created_at,
                    "sha": gem.sha256,
                    "prerelease": gem.version.chars().any(|character| character.is_ascii_alphabetic())
                })
            })
            .collect::<Vec<_>>();
        return RegistryResponse::json(200, &json!(versions)).unwrap();
    }
    if request.method == "GET"
        && let Some(filename) = path.strip_prefix("/downloads/")
        && let Some(gem) = fixture
            .rubygems
            .iter()
            .find(|gem| gem.filename() == filename)
    {
        return binary_response("application/octet-stream", gem.bytes.clone());
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
        let (version, dependency) = if id == "fixture.prerelease" {
            ("1.1.0-beta.1", None)
        } else if id == "fixture.root" {
            ("1.0.0", Some("Fixture.Dependency"))
        } else {
            ("1.0.0", None)
        };
        return RegistryResponse::json(200, &json!({"items":[{"count":1,"items":[{"catalogEntry":{"version":version,"published":"2020-01-01T00:00:00Z","dependencyGroups":dependency.map(|name| json!([{ "dependencies":[{"id":name,"range":"[1.0.0]"}]}])).unwrap_or(json!([]))},"packageContent":format!("{base_url}/packages/{id}.{version}.nupkg")}]}]})).unwrap();
    }
    if request.method == "GET" && path.starts_with("/flat/") && path.ends_with("/index.json") {
        let version = if path.contains("fixture.prerelease") {
            "1.1.0-beta.1"
        } else {
            "1.0.0"
        };
        return RegistryResponse::json(200, &json!({"versions":[version]})).unwrap();
    }
    if request.method == "GET" && path.starts_with("/packages/") {
        let name = path.trim_start_matches("/packages/");
        if let Some(bytes) = fixture.nuget_packages.get(name) {
            return binary_response("application/octet-stream", bytes.clone());
        }
    }

    if request.method == "GET" {
        if path == format!("/{GO_MODULE}/@v/list") {
            return RegistryResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: b"v1.0.0\n".to_vec(),
            };
        }
        if path == format!("/{GO_MODULE}/@latest") || path == format!("/{GO_MODULE}/@v/v1.0.0.info")
        {
            return RegistryResponse::json(
                200,
                &json!({"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}),
            )
            .unwrap();
        }
        if path == format!("/{GO_MODULE}/@v/v1.0.0.mod") {
            return RegistryResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: b"module example.com/fixture\n\ngo 1.24\n".to_vec(),
            };
        }
        if path == format!("/{GO_MODULE}/@v/v1.0.0.zip") {
            return binary_response("application/zip", go_module_zip());
        }
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

fn e2e_vulnerability() -> serde_json::Value {
    json!({
        "id": "GHSA-e2e-vulnerable",
        "modified": "2026-07-11T00:00:00Z",
        "summary": "hermetic package-manager vulnerability fixture",
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }]
    })
}

fn create_maven_files() -> HashMap<String, MavenFileFixture> {
    let mut files = HashMap::new();
    let group_path = MAVEN_GROUP.replace('.', "/");
    let metadata = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><metadata><groupId>{MAVEN_GROUP}</groupId><artifactId>{MAVEN_ROOT}</artifactId><versioning><latest>1.0.1</latest><release>1.0.1</release><versions><version>1.0.0</version><version>1.0.1</version></versions><lastUpdated>20260711000000</lastUpdated></versioning></metadata>"
    );
    insert_maven_file(
        &mut files,
        format!("/{group_path}/{MAVEN_ROOT}/maven-metadata.xml"),
        "application/xml",
        metadata.into_bytes(),
    );

    for version in ["1.0.0", "1.0.1"] {
        let jar = maven_jar(MAVEN_ROOT, version);
        let module = gradle_module_metadata(version, &jar);
        let pom = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><project xmlns=\"http://maven.apache.org/POM/4.0.0\"><modelVersion>4.0.0</modelVersion><groupId>{MAVEN_GROUP}</groupId><artifactId>{MAVEN_ROOT}</artifactId><version>{version}</version><!-- do_not_remove: published-with-gradle-metadata --><dependencies><dependency><groupId>{MAVEN_GROUP}</groupId><artifactId>{MAVEN_DEPENDENCY}</artifactId><version>1.0.0</version></dependency></dependencies></project>"
        );
        let base = format!("/{group_path}/{MAVEN_ROOT}/{version}");
        insert_maven_file(
            &mut files,
            format!("{base}/{MAVEN_ROOT}-{version}.pom"),
            "application/xml",
            pom.into_bytes(),
        );
        insert_maven_file(
            &mut files,
            format!("{base}/{MAVEN_ROOT}-{version}.jar"),
            "application/java-archive",
            jar,
        );
        insert_maven_file(
            &mut files,
            format!("{base}/{MAVEN_ROOT}-{version}.module"),
            "application/json",
            module,
        );
    }

    for artifact in [MAVEN_DEPENDENCY, MAVEN_GRADLE_DEPENDENCY] {
        let version = "1.0.0";
        let pom = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><project xmlns=\"http://maven.apache.org/POM/4.0.0\"><modelVersion>4.0.0</modelVersion><groupId>{MAVEN_GROUP}</groupId><artifactId>{artifact}</artifactId><version>{version}</version></project>"
        );
        let base = format!("/{group_path}/{artifact}/{version}");
        insert_maven_file(
            &mut files,
            format!("{base}/{artifact}-{version}.pom"),
            "application/xml",
            pom.into_bytes(),
        );
        insert_maven_file(
            &mut files,
            format!("{base}/{artifact}-{version}.jar"),
            "application/java-archive",
            maven_jar(artifact, version),
        );
    }

    for version in ["1.0.0", "1.0.1"] {
        let pom = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><project xmlns=\"http://maven.apache.org/POM/4.0.0\"><modelVersion>4.0.0</modelVersion><groupId>{MAVEN_GROUP}</groupId><artifactId>{MAVEN_BOM}</artifactId><version>{version}</version><packaging>pom</packaging><dependencyManagement><dependencies><dependency><groupId>{MAVEN_GROUP}</groupId><artifactId>{MAVEN_DEPENDENCY}</artifactId><version>1.0.0</version></dependency></dependencies></dependencyManagement></project>"
        );
        let base = format!("/{group_path}/{MAVEN_BOM}/{version}");
        insert_maven_file(
            &mut files,
            format!("{base}/{MAVEN_BOM}-{version}.pom"),
            "application/xml",
            pom.into_bytes(),
        );
    }
    files
}

fn insert_maven_file(
    files: &mut HashMap<String, MavenFileFixture>,
    path: String,
    content_type: &'static str,
    bytes: Vec<u8>,
) {
    files.insert(
        path,
        MavenFileFixture {
            content_type,
            bytes,
        },
    );
}

fn maven_jar(artifact: &str, version: &str) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())
        .unwrap();
    writer
        .write_all(
            format!("Manifest-Version: 1.0\nImplementation-Title: {artifact}\nImplementation-Version: {version}\n\n").as_bytes(),
        )
        .unwrap();
    writer.finish().unwrap().into_inner()
}

fn gradle_module_metadata(version: &str, jar: &[u8]) -> Vec<u8> {
    let remainder = serde_json::to_string(&json!({
        "component": {
            "group": MAVEN_GROUP,
            "module": MAVEN_ROOT,
            "version": version
        },
        "createdBy": { "gradle": { "version": "8.14.3" } },
        "variants": [{
            "name": "runtimeElements",
            "attributes": {
                "org.gradle.category": "library",
                "org.gradle.dependency.bundling": "external",
                "org.gradle.jvm.version": 8,
                "org.gradle.libraryelements": "jar",
                "org.gradle.usage": "java-runtime"
            },
            "dependencies": [{
                "group": MAVEN_GROUP,
                "module": MAVEN_GRADLE_DEPENDENCY,
                "version": { "requires": "1.0.0" }
            }],
            "files": [{
                "name": format!("{MAVEN_ROOT}-{version}.jar"),
                "url": format!("{MAVEN_ROOT}-{version}.jar"),
                "size": jar.len(),
                "sha256": sha256_hex(jar)
            }]
        }]
    }))
    .unwrap();
    format!("{{\"formatVersion\":\"1.1\",{}", &remainder[1..]).into_bytes()
}

fn is_e2e_vulnerable_query(query: &serde_json::Value) -> bool {
    let version = query["version"].as_str().unwrap_or_default();
    let ecosystem = query["package"]["ecosystem"].as_str().unwrap_or_default();
    let name = query["package"]["name"].as_str().unwrap_or_default();
    version == "1.0.1"
        || (ecosystem == "Go" && name == GO_MODULE && version == "1.0.0")
        || (ecosystem == "NuGet" && name.eq_ignore_ascii_case(NUGET_ROOT) && version == "1.0.0")
        || (ecosystem == "RubyGems" && name == RUBYGEMS_ROOT && version == "1.0.1")
}

fn go_module_zip() -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let prefix = "example.com/fixture@v1.0.0/";
    writer
        .start_file(format!("{prefix}go.mod"), SimpleFileOptions::default())
        .unwrap();
    writer
        .write_all(b"module example.com/fixture\n\ngo 1.24\n")
        .unwrap();
    writer
        .start_file(format!("{prefix}fixture.go"), SimpleFileOptions::default())
        .unwrap();
    writer
        .write_all(b"package fixture\n\nconst Value = 1\n")
        .unwrap();
    writer.finish().unwrap().into_inner()
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

fn rubygems_info(fixture: &FixtureArtifacts, name: &str) -> String {
    let mut body = "---\n".to_string();
    for gem in fixture.rubygems.iter().filter(|gem| gem.name == name) {
        let key = if gem.platform == "ruby" {
            gem.version.clone()
        } else {
            format!("{}-{}", gem.version, gem.platform)
        };
        let dependencies = gem
            .dependencies
            .iter()
            .map(|(name, requirement)| format!("{name}:{requirement}"))
            .collect::<Vec<_>>()
            .join(",");
        body.push_str(&format!(
            "{key} {dependencies}|checksum:{},ruby:>= 2.6.0,created_at:{}\n",
            gem.sha256, gem.created_at
        ));
    }
    body
}

fn create_rubygems(root: &Path) -> Vec<RubyGemFixture> {
    let platform_output = Command::new("ruby")
        .args(["-rrubygems", "-e", "print Gem::Platform.local.to_s"])
        .output()
        .unwrap();
    assert_success("detect local RubyGems platform", &platform_output);
    let local_platform = String::from_utf8(platform_output.stdout).unwrap();
    [
        (
            RUBYGEMS_DEPENDENCY,
            "1.0.0",
            "ruby",
            Vec::<(&str, &str)>::new(),
        ),
        (
            RUBYGEMS_ROOT,
            "1.0.0",
            "ruby",
            vec![(RUBYGEMS_DEPENDENCY, "= 1.0.0")],
        ),
        (
            RUBYGEMS_ROOT,
            "1.0.1",
            "ruby",
            vec![(RUBYGEMS_DEPENDENCY, "= 1.0.0")],
        ),
        (
            RUBYGEMS_PLATFORM,
            "1.0.0",
            local_platform.as_str(),
            Vec::new(),
        ),
        (RUBYGEMS_PRERELEASE, "1.1.0.pre.1", "ruby", Vec::new()),
    ]
    .into_iter()
    .map(|(name, version, platform, dependencies)| {
        build_rubygem(root, name, version, platform, dependencies)
    })
    .collect()
}

fn build_rubygem(
    root: &Path,
    name: &str,
    version: &str,
    platform: &str,
    dependencies: Vec<(&str, &str)>,
) -> RubyGemFixture {
    let directory = root.join(format!("rubygem-{name}-{version}-{platform}"));
    fs::create_dir_all(directory.join("lib")).unwrap();
    let module = name.replace('-', "_");
    write_file(
        &directory.join("lib").join(format!("{module}.rb")),
        &format!(
            "module {}; VERSION = \"{version}\"; end\n",
            ruby_constant(name)
        ),
    );
    let dependency_lines = dependencies
        .iter()
        .map(|(dependency, requirement)| {
            format!("  spec.add_runtime_dependency \"{dependency}\", \"{requirement}\"\n")
        })
        .collect::<String>();
    write_file(
        &directory.join("fixture.gemspec"),
        &format!(
            "Gem::Specification.new do |spec|\n  spec.name = \"{name}\"\n  spec.version = \"{version}\"\n  spec.summary = \"osv-proxy fixture\"\n  spec.authors = [\"test\"]\n  spec.files = [\"lib/{module}.rb\"]\n  spec.require_paths = [\"lib\"]\n  spec.platform = Gem::Platform.new(\"{platform}\")\n{dependency_lines}end\n"
        ),
    );
    let expected_filename = if platform == "ruby" {
        format!("{name}-{version}.gem")
    } else {
        format!("{name}-{version}-{platform}.gem")
    };
    let output_path = directory.join(&expected_filename);
    let output = Command::new("gem")
        .args(["build", "fixture.gemspec", "--output"])
        .arg(&output_path)
        .current_dir(&directory)
        .output()
        .unwrap();
    assert_success("build RubyGem fixture", &output);
    let bytes = fs::read(&output_path).unwrap();
    RubyGemFixture {
        name: name.into(),
        version: version.into(),
        platform: platform.into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        dependencies: dependencies
            .into_iter()
            .map(|(name, requirement)| (name.into(), requirement.into()))
            .collect(),
        sha256: sha256_hex(&bytes),
        bytes,
    }
}

fn ruby_constant(name: &str) -> String {
    name.split(['-', '_', '.'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            characters
                .next()
                .map(|first| format!("{}{}", first.to_ascii_uppercase(), characters.as_str()))
                .unwrap_or_default()
        })
        .collect()
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
        ("fixture.prerelease", "Fixture.Prerelease", None),
    ]
    .into_iter()
    .map(|(key, id, dependency)| {
        let version = if key == "fixture.prerelease" { "1.1.0-beta.1" } else { "1.0.0" };
        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer.start_file(format!("{id}.nuspec"), SimpleFileOptions::default()).unwrap();
        let dependencies = dependency.map(|dep| format!("<dependencies><dependency id=\"{dep}\" version=\"[1.0.0]\" /></dependencies>")).unwrap_or_default();
        writer.write_all(format!("<?xml version=\"1.0\"?><package><metadata><id>{id}</id><version>{version}</version><authors>test</authors><description>fixture</description>{dependencies}</metadata></package>").as_bytes()).unwrap();
        (format!("{key}.{version}.nupkg"), writer.finish().unwrap().into_inner())
    })
    .collect()
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

fn text_response(body: String) -> RegistryResponse {
    let etag = format!("\"{:x}\"", md5::compute(body.as_bytes()));
    RegistryResponse {
        status: 200,
        headers: vec![
            ("content-type".into(), "text/plain; charset=utf-8".into()),
            ("etag".into(), etag),
            ("accept-ranges".into(), "bytes".into()),
        ],
        body: body.into_bytes(),
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

fn replace_file_text(path: &Path, from: &str, to: &str) {
    let contents = fs::read_to_string(path).unwrap();
    write_file(path, &contents.replace(from, to));
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
