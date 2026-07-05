use crate::artifact::parse_identity;
use crate::config::Config;
use crate::malicious::OsvHttpClient;
use crate::policy::PolicyEngine;
use crate::server;
use anyhow::Context;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
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
    Check {
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
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    Validate {
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
        Command::Check {
            package,
            config,
            published_at,
        } => {
            let config = Config::load(&config)
                .with_context(|| format!("config validation failed for {}", config.display()))?;
            let artifact = parse_identity(&package, published_at)?;
            let checker = OsvHttpClient::new(&config.policy.malicious.osv_api_url);
            let decision = PolicyEngine::new(&config)
                .evaluate(&artifact, Utc::now(), &checker)
                .await;
            println!("{}", serde_json::to_string_pretty(&decision)?);
            if decision.allowed {
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
            println!("configuration is valid for phase one");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

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
            Command::Check {
                package, config, ..
            } => {
                let artifact = parse_identity(&package, None).unwrap();
                assert_eq!(artifact.name, "@babel/core");
                assert_eq!(artifact.version, "7.24.0");
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
                let artifact = parse_identity(&package, None).unwrap();
                assert_eq!(artifact.identity(), "pypi:my-package@1.0.0");
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
            "examples/phase1/osv-proxy.yaml",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Config {
                command: ConfigCommand::Validate { .. }
            }
        ));
    }
}
