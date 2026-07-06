use crate::artifact::{normalize_pypi_name, Ecosystem};
use chrono::Duration as ChronoDuration;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub upstreams: UpstreamsConfig,
    pub policy: PolicyConfig,
    pub artifacts: ArtifactsConfig,
    pub allowlist: Vec<AllowlistEntry>,
    pub blocklist: Vec<BlocklistEntry>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path)?;
        let config = serde_yaml::from_str::<Config>(&raw)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        ChronoDuration::from_std(self.policy.minimum_age).map_err(|_| {
            ConfigError::Invalid(
                "policy.minimum_age is too large for policy evaluation".to_string(),
            )
        })?;
        if self.artifacts.behavior == ArtifactBehavior::ProxyCacheS3 {
            return Err(ConfigError::Unsupported(
                "artifacts.behavior=proxy_cache_s3 is not supported yet".to_string(),
            ));
        }
        for entry in &self.allowlist {
            if entry.version == "*" {
                return Err(ConfigError::Unsupported(
                    "allowlist entries must use exact versions".to_string(),
                ));
            }
            if entry.bypass_osv && entry.reason.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "allowlist entries with bypass_osv=true require a reason".to_string(),
                ));
            }
        }
        for entry in &self.blocklist {
            if entry.versions.is_empty() {
                return Err(ConfigError::Invalid(
                    "blocklist entries must include at least one version".to_string(),
                ));
            }
            for version in &entry.versions {
                if version != "*" && looks_like_range(version) {
                    return Err(ConfigError::Unsupported(
                        "blocklist entries support only exact versions and *".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: String,
    pub public_base_url: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".to_string(),
            public_base_url: "http://127.0.0.1:8080".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamsConfig {
    pub npm: NpmUpstreamConfig,
    pub pypi: PypiUpstreamConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NpmUpstreamConfig {
    pub registry_url: String,
}

impl Default for NpmUpstreamConfig {
    fn default() -> Self {
        Self {
            registry_url: "https://registry.npmjs.org".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PypiUpstreamConfig {
    pub simple_url: String,
}

impl Default for PypiUpstreamConfig {
    fn default() -> Self {
        Self {
            simple_url: "https://pypi.org/simple".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(with = "duration_format")]
    pub minimum_age: Duration,
    pub missing_publish_time: MissingPublishTime,
    pub osv: OsvConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            minimum_age: Duration::from_secs(72 * 60 * 60),
            missing_publish_time: MissingPublishTime::Block,
            osv: OsvConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingPublishTime {
    Block,
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OsvConfig {
    pub block_malicious: bool,
    pub api_url: String,
    pub on_error: OsvErrorBehavior,
}

impl Default for OsvConfig {
    fn default() -> Self {
        Self {
            block_malicious: true,
            api_url: "https://api.osv.dev".to_string(),
            on_error: OsvErrorBehavior::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsvErrorBehavior {
    Block,
    Allow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactsConfig {
    pub behavior: ArtifactBehavior,
}

impl Default for ArtifactsConfig {
    fn default() -> Self {
        Self {
            behavior: ArtifactBehavior::Redirect,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactBehavior {
    #[default]
    Redirect,
    Proxy,
    ProxyCacheS3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub bypass_age_gate: bool,
    #[serde(default)]
    pub bypass_osv: bool,
    #[serde(default)]
    pub reason: String,
}

impl AllowlistEntry {
    pub fn normalized_name(&self) -> String {
        match self.ecosystem {
            Ecosystem::Npm => self.name.clone(),
            Ecosystem::Pypi => normalize_pypi_name(&self.name),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlocklistEntry {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub versions: Vec<String>,
    #[serde(default)]
    pub reason: String,
}

impl BlocklistEntry {
    pub fn normalized_name(&self) -> String {
        match self.ecosystem {
            Ecosystem::Npm => self.name.clone(),
            Ecosystem::Pypi => normalize_pypi_name(&self.name),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unsupported configuration: {0}")]
    Unsupported(String),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

fn looks_like_range(version: &str) -> bool {
    version.contains('<')
        || version.contains('>')
        || version.contains('=')
        || version.contains('~')
        || version.contains('^')
        || version.contains(',')
        || version.contains(' ')
}

mod duration_format {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&humantime::format_duration(*duration).to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        humantime::parse_duration(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(raw: &str) -> Result<Config, ConfigError> {
        let config = serde_yaml::from_str::<Config>(raw)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn defaults_are_conservative() {
        let config = Config::default();
        assert_eq!(config.policy.minimum_age, Duration::from_secs(72 * 60 * 60));
        assert_eq!(
            config.policy.missing_publish_time,
            MissingPublishTime::Block
        );
        assert!(config.policy.osv.block_malicious);
        assert_eq!(config.policy.osv.on_error, OsvErrorBehavior::Block);
        assert_eq!(config.policy.osv.api_url, "https://api.osv.dev");
        assert_eq!(config.artifacts.behavior, ArtifactBehavior::Redirect);
        config.validate().unwrap();
    }

    #[test]
    fn documented_config_validates() {
        let config = load(
            r#"
server:
  bind: "127.0.0.1:8080"
  public_base_url: "http://127.0.0.1:8080"
policy:
  minimum_age: "72h"
  missing_publish_time: "block"
  osv:
    block_malicious: false
    on_error: "block"
"#,
        )
        .unwrap();

        assert!(!config.policy.osv.block_malicious);
        assert_eq!(config.policy.osv.on_error, OsvErrorBehavior::Block);
        assert_eq!(config.policy.osv.api_url, "https://api.osv.dev");
        assert_eq!(config.artifacts.behavior, ArtifactBehavior::Redirect);
    }

    #[test]
    fn artifact_redirect_behavior_validates() {
        let config = load(
            r#"
artifacts:
  behavior: redirect
"#,
        )
        .unwrap();

        assert_eq!(config.artifacts.behavior, ArtifactBehavior::Redirect);
    }

    #[test]
    fn artifact_proxy_behavior_validates() {
        let config = load(
            r#"
artifacts:
  behavior: proxy
"#,
        )
        .unwrap();

        assert_eq!(config.artifacts.behavior, ArtifactBehavior::Proxy);
    }

    #[test]
    fn rejects_unsupported_artifact_proxy_cache_s3_behavior() {
        let err = load(
            r#"
artifacts:
  behavior: proxy_cache_s3
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("proxy_cache_s3 is not supported"));
    }

    #[test]
    fn rejects_unknown_artifacts_config_key() {
        let err = load(
            r#"
artifacts:
  behavior: proxy
  typo: true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `typo`"));
    }

    #[test]
    fn rejects_old_malicious_section() {
        let err = load(
            r#"
policy:
  malicious:
    mode: local
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `malicious`"));
    }

    #[test]
    fn rejects_metadata_cache_config() {
        let err = load(
            r#"
metadata_cache:
  enabled: true
  backend: cachebox
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `metadata_cache`"));
    }

    #[test]
    fn rejects_malicious_store_config() {
        let err = load(
            r#"
malicious_store:
  mongodb:
    uri: mongodb://127.0.0.1:27017
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `malicious_store`"));
    }

    #[test]
    fn rejects_allowlist_wildcard() {
        let err = load(
            r#"
allowlist:
  - ecosystem: npm
    name: lodash
    version: "*"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exact versions"));
    }

    #[test]
    fn rejects_blocklist_ranges() {
        let err = load(
            r#"
blocklist:
  - ecosystem: npm
    name: lodash
    versions: ["<4.17.21"]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exact versions and *"));
    }

    #[test]
    fn rejects_unknown_top_level_config_key() {
        let err = load(
            r#"
typo: true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `typo`"));
    }

    #[test]
    fn rejects_unknown_server_config_key() {
        let err = load(
            r#"
server:
  bind: "127.0.0.1:8080"
  typo: true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `typo`"));
    }

    #[test]
    fn rejects_unknown_policy_config_key() {
        let err = load(
            r#"
policy:
  typo: true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `typo`"));
    }

    #[test]
    fn rejects_unknown_osv_config_key() {
        let err = load(
            r#"
policy:
  osv:
    typo: true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `typo`"));
    }

    #[test]
    fn rejects_old_osv_mal_id_filter_flag() {
        let err = load(
            r#"
policy:
  osv:
    only_mal_ids: true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `only_mal_ids`"));
    }

    #[test]
    fn rejects_old_server_listen_key() {
        let err = load(
            r#"
server:
  listen: "127.0.0.1:8080"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `listen`"));
    }

    #[test]
    fn rejects_old_allowlist_bypass_malicious_key() {
        let err = load(
            r#"
allowlist:
  - ecosystem: npm
    name: lodash
    version: "4.17.21"
    bypass_malicious: true
    reason: "old key"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `bypass_malicious`"));
    }

    #[test]
    fn rejects_unknown_npm_upstream_config_key() {
        let err = load(
            r#"
upstreams:
  npm:
    typo: true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `typo`"));
    }

    #[test]
    fn rejects_unknown_pypi_upstream_config_key() {
        let err = load(
            r#"
upstreams:
  pypi:
    typo: true
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `typo`"));
    }

    #[test]
    fn rejects_minimum_age_too_large_for_policy_evaluation() {
        let err = load(
            r#"
policy:
  minimum_age: "18446744073709551615s"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("policy.minimum_age is too large"));
    }
}
