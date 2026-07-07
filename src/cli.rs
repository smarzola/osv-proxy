use crate::artifact::{Artifact, Ecosystem, parse_identity, parse_package_identity};
use crate::config::Config;
use crate::malicious::{HttpOsvDumpClient, MaliciousChecker, OsvHttpClient, sync_malicious};
use crate::npm::{NpmMetadataProvider, NpmRegistryClient};
use crate::policy::{Decision, PolicyEngine};
use crate::pypi::{PypiSimpleClient, PypiSimpleProvider};
use crate::server;
use anyhow::Context;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "osv-proxy",
    version,
    about = "Deterministic package policy enforcement proxy"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    #[command(about = "Check a package version against live registry metadata and policy")]
    Check {
        package: String,
        #[arg(long)]
        config: PathBuf,
    },
    #[command(about = "Evaluate a manually supplied synthetic artifact; not registry-backed")]
    Eval {
        package: String,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        published_at: Option<DateTime<Utc>>,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Malicious {
        #[command(subcommand)]
        command: MaliciousCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    Validate {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum MaliciousCommand {
    #[command(about = "Synchronize local malicious package data from OSV GCS dumps")]
    Sync {
        #[arg(long)]
        config: PathBuf,
    },
}

pub async fn run() -> anyhow::Result<()> {
    execute(Cli::parse()).await
}

pub async fn execute(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Serve { config } => {
            let config = Config::load(&config)
                .with_context(|| format!("config validation failed for {}", config.display()))?;
            server::serve(config).await
        }
        Command::Check { package, config } => {
            let config = Config::load(&config)
                .with_context(|| format!("config validation failed for {}", config.display()))?;
            let checker = OsvHttpClient::new(&config.policy.osv.api_url);
            let npm_upstream = NpmRegistryClient::new(&config.upstreams.npm.registry_url);
            let pypi_upstream = PypiSimpleClient::new(&config.upstreams.pypi.simple_url);
            let output = registry_check(
                &config,
                &package,
                Utc::now(),
                &checker,
                &npm_upstream,
                &pypi_upstream,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&output)?);
            if output.allowed {
                Ok(())
            } else {
                std::process::exit(2);
            }
        }
        Command::Eval {
            package,
            config,
            published_at,
        } => {
            let config = Config::load(&config)
                .with_context(|| format!("config validation failed for {}", config.display()))?;
            let artifact = parse_identity(&package, published_at)?;
            let checker = OsvHttpClient::new(&config.policy.osv.api_url);
            let decision = PolicyEngine::new(&config)
                .evaluate(&artifact, Utc::now(), &checker)
                .await;
            let output = synthetic_eval_output(artifact, decision);
            println!("{}", serde_json::to_string_pretty(&output)?);
            if output.allowed {
                Ok(())
            } else {
                std::process::exit(2);
            }
        }
        Command::Config {
            command: ConfigCommand::Validate { config },
        } => {
            Config::load(&config)
                .with_context(|| format!("config validation failed for {}", config.display()))?;
            println!("configuration is valid");
            Ok(())
        }
        Command::Malicious {
            command: MaliciousCommand::Sync { config },
        } => {
            let config = Config::load(&config)
                .with_context(|| format!("config validation failed for {}", config.display()))?;
            let client = HttpOsvDumpClient::new();
            let report = sync_malicious(&config.policy.osv.local, &client).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
    }
}

#[derive(Debug, Serialize)]
struct CheckOutput {
    mode: &'static str,
    package: String,
    allowed: bool,
    artifacts: Vec<ArtifactDecision>,
}

#[derive(Debug, Serialize)]
struct ArtifactDecision {
    artifact: Artifact,
    decision: Decision,
}

async fn registry_check(
    config: &Config,
    package: &str,
    now: DateTime<Utc>,
    checker: &dyn MaliciousChecker,
    npm_upstream: &dyn NpmMetadataProvider,
    pypi_upstream: &dyn PypiSimpleProvider,
) -> anyhow::Result<CheckOutput> {
    let identity = parse_package_identity(package)?;
    let artifacts = match identity.ecosystem {
        Ecosystem::Npm => vec![
            crate::npm::lookup_artifact(npm_upstream, &identity.name, &identity.version).await?,
        ],
        Ecosystem::Pypi => {
            crate::pypi::lookup_artifacts(config, pypi_upstream, &identity.name, &identity.version)
                .await?
        }
    };
    let artifacts = evaluate_artifacts(config, artifacts, now, checker).await;
    Ok(CheckOutput {
        mode: "registry",
        package: identity.identity(),
        allowed: artifacts.iter().all(|artifact| artifact.decision.allowed),
        artifacts,
    })
}

async fn evaluate_artifacts(
    config: &Config,
    artifacts: Vec<Artifact>,
    now: DateTime<Utc>,
    checker: &dyn MaliciousChecker,
) -> Vec<ArtifactDecision> {
    let policy = PolicyEngine::new(config);
    let mut decisions = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let decision = policy.evaluate(&artifact, now, checker).await;
        decisions.push(ArtifactDecision { artifact, decision });
    }
    decisions
}

fn synthetic_eval_output(artifact: Artifact, decision: Decision) -> CheckOutput {
    CheckOutput {
        mode: "synthetic",
        package: artifact.identity(),
        allowed: decision.allowed,
        artifacts: vec![ArtifactDecision { artifact, decision }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AllowlistEntry, BlocklistEntry};
    use crate::policy::DecisionReason;
    use async_trait::async_trait;
    use clap::Parser;
    use serde_json::{Map, Value, json};
    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn parses_check_for_scoped_npm_package() {
        let cli = Cli::try_parse_from([
            "osv-proxy",
            "check",
            "npm:@babel/core@7.24.0",
            "--config",
            "osv-proxy.yaml",
        ])
        .unwrap();
        match cli.command {
            Command::Check { package, config } => {
                let identity = parse_package_identity(&package).unwrap();
                assert_eq!(identity.name, "@babel/core");
                assert_eq!(identity.version, "7.24.0");
                assert_eq!(config, PathBuf::from("osv-proxy.yaml"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_pypi_package_and_normalizes_name() {
        let cli = Cli::try_parse_from([
            "osv-proxy",
            "check",
            "pypi:My_Package@1.0.0",
            "--config",
            "osv-proxy.yaml",
        ])
        .unwrap();
        match cli.command {
            Command::Check { package, .. } => {
                let identity = parse_package_identity(&package).unwrap();
                assert_eq!(identity.identity(), "pypi:my-package@1.0.0");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_synthetic_eval_with_publish_time() {
        let cli = Cli::try_parse_from([
            "osv-proxy",
            "eval",
            "npm:demo@1.0.0",
            "--config",
            "osv-proxy.yaml",
            "--published-at",
            "2026-06-01T00:00:00Z",
        ])
        .unwrap();
        match cli.command {
            Command::Eval {
                package,
                published_at,
                ..
            } => {
                assert_eq!(package, "npm:demo@1.0.0");
                assert_eq!(
                    published_at,
                    Some(
                        DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    )
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_nested_config_validate() {
        let cli = Cli::try_parse_from([
            "osv-proxy",
            "config",
            "validate",
            "--config",
            "examples/basic/osv-proxy.yaml",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Config {
                command: ConfigCommand::Validate { .. }
            }
        ));
    }

    #[test]
    fn parses_malicious_sync() {
        let cli = Cli::try_parse_from([
            "osv-proxy",
            "malicious",
            "sync",
            "--config",
            "osv-proxy.yaml",
        ])
        .unwrap();
        match cli.command {
            Command::Malicious {
                command: MaliciousCommand::Sync { config },
            } => assert_eq!(config, PathBuf::from("osv-proxy.yaml")),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    struct StaticNpm {
        metadata: HashMap<String, Value>,
    }

    #[async_trait]
    impl NpmMetadataProvider for StaticNpm {
        async fn fetch_package_metadata(
            &self,
            package: &str,
        ) -> Result<Value, crate::npm::NpmError> {
            self.metadata.get(package).cloned().ok_or_else(|| {
                crate::npm::NpmError::InvalidMetadata(format!(
                    "missing static metadata for {package}"
                ))
            })
        }
    }

    struct StaticPypi {
        projects: HashMap<String, crate::pypi::SimpleProject>,
    }

    #[async_trait]
    impl PypiSimpleProvider for StaticPypi {
        async fn fetch_simple_root(&self) -> Result<String, crate::pypi::PypiError> {
            Ok(String::new())
        }

        async fn fetch_project_json(
            &self,
            project: &str,
        ) -> Result<crate::pypi::SimpleProject, crate::pypi::PypiError> {
            self.projects.get(project).cloned().ok_or_else(|| {
                crate::pypi::PypiError::InvalidSimpleJson(format!("missing {project}"))
            })
        }
    }

    struct CleanChecker {
        calls: AtomicU32,
    }

    #[async_trait]
    impl MaliciousChecker for CleanChecker {
        async fn check(
            &self,
            _artifact: &Artifact,
        ) -> Result<Vec<crate::malicious::MaliciousHit>, crate::malicious::MaliciousError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn timestamp(raw: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(raw)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn empty_pypi() -> StaticPypi {
        StaticPypi {
            projects: HashMap::new(),
        }
    }

    fn empty_npm() -> StaticNpm {
        StaticNpm {
            metadata: HashMap::new(),
        }
    }

    fn npm_with_versions(versions: &[(&str, &str)]) -> StaticNpm {
        let mut time = Map::new();
        let mut version_metadata = Map::new();
        for (version, published_at) in versions {
            time.insert((*version).to_string(), json!(published_at));
            version_metadata.insert(
                (*version).to_string(),
                json!({
                    "dist": {
                        "tarball": format!("https://registry.example/demo/-/demo-{version}.tgz"),
                        "integrity": "sha512-allowed"
                    }
                }),
            );
        }
        StaticNpm {
            metadata: HashMap::from([(
                "demo".to_string(),
                json!({
                    "name": "demo",
                    "time": Value::Object(time),
                    "versions": Value::Object(version_metadata)
                }),
            )]),
        }
    }

    fn pypi_file(filename: &str, upload_time: DateTime<Utc>) -> crate::pypi::SimpleFile {
        crate::pypi::SimpleFile {
            filename: filename.to_string(),
            url: format!("https://files.example/{filename}"),
            hashes: BTreeMap::new(),
            requires_python: None,
            dist_info_metadata: None,
            gpg_sig: None,
            yanked: None,
            upload_time: Some(upload_time),
            extra: BTreeMap::new(),
        }
    }

    fn pypi_with_files(files: Vec<crate::pypi::SimpleFile>) -> StaticPypi {
        StaticPypi {
            projects: HashMap::from([(
                "demo".to_string(),
                crate::pypi::SimpleProject {
                    meta: BTreeMap::new(),
                    name: "demo".to_string(),
                    versions: vec!["1.0.0".to_string()],
                    files,
                },
            )]),
        }
    }

    #[tokio::test]
    async fn registry_check_uses_npm_metadata_publish_time() {
        let config = Config::default();
        let npm = StaticNpm {
            metadata: HashMap::from([(
                "demo".to_string(),
                json!({
                    "name": "demo",
                    "time": { "1.0.0": "2026-06-01T00:00:00Z" },
                    "versions": {
                        "1.0.0": {
                            "dist": {
                                "tarball": "https://registry.example/demo/-/demo-1.0.0.tgz",
                                "integrity": "sha512-allowed"
                            }
                        }
                    }
                }),
            )]),
        };
        let pypi = StaticPypi {
            projects: HashMap::new(),
        };
        let checker = CleanChecker {
            calls: AtomicU32::new(0),
        };

        let output = registry_check(
            &config,
            "npm:demo@1.0.0",
            fixed_now(),
            &checker,
            &npm,
            &pypi,
        )
        .await
        .unwrap();

        assert_eq!(output.mode, "registry");
        assert!(output.allowed);
        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(
            output.artifacts[0].artifact.filename.as_deref(),
            Some("demo-1.0.0.tgz")
        );
        assert_eq!(
            output.artifacts[0].decision.published_at,
            Some(
                DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );
        assert_eq!(checker.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn registry_check_blocks_too_new_npm_metadata() {
        let config = Config::default();
        let npm = npm_with_versions(&[("2.0.0", "2026-07-05T00:00:00Z")]);
        let pypi = empty_pypi();
        let checker = CleanChecker {
            calls: AtomicU32::new(0),
        };

        let output = registry_check(
            &config,
            "npm:demo@2.0.0",
            fixed_now(),
            &checker,
            &npm,
            &pypi,
        )
        .await
        .unwrap();

        assert!(!output.allowed);
        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(
            output.artifacts[0].decision.reason,
            DecisionReason::TooYoung
        );
    }

    #[tokio::test]
    async fn registry_check_allows_old_pypi_upload_time() {
        let mut config = Config::default();
        config.upstreams.pypi.simple_url = "https://pypi.example/simple".to_string();
        let pypi = pypi_with_files(vec![pypi_file(
            "demo-1.0.0.tar.gz",
            timestamp("2026-06-01T00:00:00Z"),
        )]);
        let npm = empty_npm();
        let checker = CleanChecker {
            calls: AtomicU32::new(0),
        };

        let output = registry_check(
            &config,
            "pypi:demo@1.0.0",
            fixed_now(),
            &checker,
            &npm,
            &pypi,
        )
        .await
        .unwrap();

        assert!(output.allowed);
        assert_eq!(output.artifacts.len(), 1);
        assert_eq!(output.artifacts[0].decision.reason, DecisionReason::Allowed);
        assert_eq!(
            output.artifacts[0].decision.published_at,
            Some(timestamp("2026-06-01T00:00:00Z"))
        );
    }

    #[tokio::test]
    async fn registry_check_fails_when_npm_version_is_missing() {
        let config = Config::default();
        let npm = npm_with_versions(&[("1.0.0", "2026-06-01T00:00:00Z")]);
        let pypi = empty_pypi();
        let checker = CleanChecker {
            calls: AtomicU32::new(0),
        };

        let err = registry_check(
            &config,
            "npm:demo@9.9.9",
            fixed_now(),
            &checker,
            &npm,
            &pypi,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("npm version not found"));
    }

    #[tokio::test]
    async fn registry_check_fails_when_pypi_version_is_missing() {
        let config = Config::default();
        let pypi = pypi_with_files(vec![pypi_file(
            "demo-1.0.0.tar.gz",
            timestamp("2026-06-01T00:00:00Z"),
        )]);
        let npm = empty_npm();
        let checker = CleanChecker {
            calls: AtomicU32::new(0),
        };

        let err = registry_check(
            &config,
            "pypi:demo@9.9.9",
            fixed_now(),
            &checker,
            &npm,
            &pypi,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("PyPI version not found"));
    }

    #[tokio::test]
    async fn registry_check_respects_manual_blocklist() {
        let mut config = Config::default();
        config.blocklist.push(BlocklistEntry {
            ecosystem: Ecosystem::Npm,
            name: "demo".to_string(),
            versions: vec!["1.0.0".to_string()],
            reason: "blocked".to_string(),
        });
        let npm = npm_with_versions(&[("1.0.0", "2026-06-01T00:00:00Z")]);
        let pypi = empty_pypi();
        let checker = CleanChecker {
            calls: AtomicU32::new(0),
        };

        let output = registry_check(
            &config,
            "npm:demo@1.0.0",
            fixed_now(),
            &checker,
            &npm,
            &pypi,
        )
        .await
        .unwrap();

        assert!(!output.allowed);
        assert_eq!(
            output.artifacts[0].decision.reason,
            DecisionReason::ManuallyBlocked
        );
    }

    #[tokio::test]
    async fn registry_check_respects_allowlist_age_bypass() {
        let mut config = Config::default();
        config.allowlist.push(AllowlistEntry {
            ecosystem: Ecosystem::Npm,
            name: "demo".to_string(),
            version: "2.0.0".to_string(),
            bypass_age_gate: true,
            bypass_osv: true,
            reason: "approved exception".to_string(),
        });
        let npm = npm_with_versions(&[("2.0.0", "2026-07-05T00:00:00Z")]);
        let pypi = empty_pypi();
        let checker = CleanChecker {
            calls: AtomicU32::new(0),
        };

        let output = registry_check(
            &config,
            "npm:demo@2.0.0",
            fixed_now(),
            &checker,
            &npm,
            &pypi,
        )
        .await
        .unwrap();

        assert!(output.allowed);
        assert_eq!(
            output.artifacts[0].decision.reason,
            DecisionReason::Allowlisted
        );
        assert_eq!(checker.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn registry_check_reports_pypi_file_decisions() {
        let mut config = Config::default();
        config.upstreams.pypi.simple_url = "https://pypi.example/simple".to_string();
        let upload_time = DateTime::parse_from_rfc3339("2026-07-05T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let pypi = StaticPypi {
            projects: HashMap::from([(
                "demo".to_string(),
                crate::pypi::SimpleProject {
                    meta: BTreeMap::new(),
                    name: "demo".to_string(),
                    versions: vec!["1.0.0".to_string()],
                    files: vec![
                        crate::pypi::SimpleFile {
                            filename: "demo-1.0.0.tar.gz".to_string(),
                            url: "https://files.example/demo-1.0.0.tar.gz".to_string(),
                            hashes: BTreeMap::new(),
                            requires_python: None,
                            dist_info_metadata: None,
                            gpg_sig: None,
                            yanked: None,
                            upload_time: Some(upload_time),
                            extra: BTreeMap::new(),
                        },
                        crate::pypi::SimpleFile {
                            filename: "demo-1.0.0-py3-none-any.whl".to_string(),
                            url: "https://files.example/demo-1.0.0-py3-none-any.whl".to_string(),
                            hashes: BTreeMap::new(),
                            requires_python: None,
                            dist_info_metadata: None,
                            gpg_sig: None,
                            yanked: None,
                            upload_time: Some(upload_time),
                            extra: BTreeMap::new(),
                        },
                    ],
                },
            )]),
        };
        let npm = StaticNpm {
            metadata: HashMap::new(),
        };
        let checker = CleanChecker {
            calls: AtomicU32::new(0),
        };

        let output = registry_check(
            &config,
            "pypi:Demo@1.0.0",
            fixed_now(),
            &checker,
            &npm,
            &pypi,
        )
        .await
        .unwrap();

        assert_eq!(output.package, "pypi:demo@1.0.0");
        assert!(!output.allowed);
        assert_eq!(output.artifacts.len(), 2);
        assert!(
            output
                .artifacts
                .iter()
                .all(|artifact| !artifact.decision.allowed)
        );
        assert_eq!(checker.calls.load(Ordering::SeqCst), 2);
    }
}
