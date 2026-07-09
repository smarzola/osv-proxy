use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pypi,
    Go,
    #[serde(rename = "crates.io")]
    CratesIo,
    Nuget,
}

impl Ecosystem {
    pub fn normalize_name(self, name: &str) -> String {
        match self {
            Ecosystem::Npm => name.to_string(),
            Ecosystem::Pypi => normalize_pypi_name(name),
            Ecosystem::Go => name.to_string(),
            Ecosystem::CratesIo => normalize_cargo_name(name),
            Ecosystem::Nuget => normalize_nuget_name(name),
        }
    }

    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "PyPI",
            Ecosystem::Go => "Go",
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Nuget => "NuGet",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::Pypi => write!(f, "pypi"),
            Ecosystem::Go => write!(f, "go"),
            Ecosystem::CratesIo => write!(f, "crates.io"),
            Ecosystem::Nuget => write!(f, "nuget"),
        }
    }
}

impl FromStr for Ecosystem {
    type Err = ArtifactParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "npm" => Ok(Ecosystem::Npm),
            "pypi" | "python" | "python-package" => Ok(Ecosystem::Pypi),
            "go" | "golang" | "go-module" => Ok(Ecosystem::Go),
            "crates.io" | "cargo" | "crates-io" => Ok(Ecosystem::CratesIo),
            "nuget" | "nuget.org" | "dotnet" => Ok(Ecosystem::Nuget),
            other => Err(ArtifactParseError::UnsupportedEcosystem(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ArtifactHashes {
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub integrity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub filename: Option<String>,
    pub upstream_url: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub hashes: ArtifactHashes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

impl PackageIdentity {
    pub fn identity(&self) -> String {
        format!("{}:{}@{}", self.ecosystem, self.name, self.version)
    }
}

impl Artifact {
    pub fn package(
        ecosystem: Ecosystem,
        name: impl AsRef<str>,
        version: impl Into<String>,
        published_at: Option<DateTime<Utc>>,
    ) -> Self {
        let normalized_name = ecosystem.normalize_name(name.as_ref());
        Self {
            ecosystem,
            name: normalized_name,
            version: version.into(),
            filename: None,
            upstream_url: None,
            published_at,
            hashes: ArtifactHashes::default(),
        }
    }

    pub fn identity(&self) -> String {
        format!("{}:{}@{}", self.ecosystem, self.name, self.version)
    }
}

pub fn parse_identity(
    value: &str,
    published_at: Option<DateTime<Utc>>,
) -> Result<Artifact, ArtifactParseError> {
    let identity = parse_package_identity(value)?;
    Ok(Artifact::package(
        identity.ecosystem,
        identity.name,
        identity.version,
        published_at,
    ))
}

pub fn parse_package_identity(value: &str) -> Result<PackageIdentity, ArtifactParseError> {
    let (ecosystem, rest) = value
        .split_once(':')
        .ok_or_else(|| ArtifactParseError::InvalidIdentity(value.to_string()))?;
    let ecosystem = Ecosystem::from_str(ecosystem)?;
    let version_separator = rest
        .rfind('@')
        .ok_or_else(|| ArtifactParseError::InvalidIdentity(value.to_string()))?;
    if version_separator == 0 && !rest.starts_with('@') {
        return Err(ArtifactParseError::InvalidIdentity(value.to_string()));
    }
    let (name, version_with_at) = rest.split_at(version_separator);
    let version = &version_with_at[1..];
    if name.is_empty() || version.is_empty() {
        return Err(ArtifactParseError::InvalidIdentity(value.to_string()));
    }
    Ok(PackageIdentity {
        ecosystem,
        name: ecosystem.normalize_name(name),
        version: normalize_version(ecosystem, version)?,
    })
}

pub fn normalize_pypi_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut previous_was_separator = false;
    for ch in name.chars().flat_map(char::to_lowercase) {
        if matches!(ch, '-' | '_' | '.') {
            if !previous_was_separator {
                out.push('-');
                previous_was_separator = true;
            }
        } else {
            out.push(ch);
            previous_was_separator = false;
        }
    }
    out.trim_matches('-').to_string()
}

pub fn normalize_cargo_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

pub fn normalize_nuget_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// Normalizes the NuGet identity form used by V3 URLs and OSV. NuGet accepts
/// one to four numeric components, strips build metadata, and treats a trailing
/// zero revision as absent.
pub fn normalize_nuget_version(value: &str) -> Result<String, ArtifactParseError> {
    let value_without_build = value.split_once('+').map_or(value, |(base, _)| base);
    let (core, prerelease) = value
        .split_once('+')
        .map_or(value, |(base, _)| base)
        .split_once('-')
        .map_or((value_without_build, None), |(a, b)| (a, Some(b)));
    let mut parts = core
        .split('.')
        .map(|part| {
            (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| part.parse::<u64>().ok())
                .flatten()
                .ok_or_else(|| ArtifactParseError::InvalidNugetVersion(value.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parts.is_empty() || parts.len() > 4 {
        return Err(ArtifactParseError::InvalidNugetVersion(value.to_string()));
    }
    while parts.len() < 3 {
        parts.push(0);
    }
    if parts.len() == 4 && parts[3] == 0 {
        parts.pop();
    }
    let mut normalized = parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".");
    if let Some(prerelease) = prerelease {
        if prerelease.is_empty()
            || !prerelease
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        {
            return Err(ArtifactParseError::InvalidNugetVersion(value.to_string()));
        }
        normalized.push('-');
        normalized.push_str(&prerelease.to_ascii_lowercase());
    }
    Ok(normalized)
}

fn normalize_version(ecosystem: Ecosystem, value: &str) -> Result<String, ArtifactParseError> {
    match ecosystem {
        Ecosystem::Nuget => normalize_nuget_version(value),
        _ => Ok(value.to_string()),
    }
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactParseError {
    #[error("unsupported ecosystem: {0}")]
    UnsupportedEcosystem(String),
    #[error("expected package identity in the form ecosystem:name@version: {0}")]
    InvalidIdentity(String),
    #[error("invalid NuGet version: {0}")]
    InvalidNugetVersion(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scoped_npm_identity() {
        let artifact = parse_identity("npm:@babel/core@7.24.0", None).unwrap();
        assert_eq!(artifact.ecosystem, Ecosystem::Npm);
        assert_eq!(artifact.name, "@babel/core");
        assert_eq!(artifact.version, "7.24.0");
        assert_eq!(artifact.identity(), "npm:@babel/core@7.24.0");
    }

    #[test]
    fn normalizes_pypi_identity() {
        let artifact = parse_identity("pypi:My_Package.Name@1.0.0", None).unwrap();
        assert_eq!(artifact.name, "my-package-name");
        assert_eq!(artifact.identity(), "pypi:my-package-name@1.0.0");
    }

    #[test]
    fn parses_package_identity_without_constructing_artifact() {
        let identity = parse_package_identity("npm:@babel/core@7.24.0").unwrap();
        assert_eq!(identity.ecosystem, Ecosystem::Npm);
        assert_eq!(identity.name, "@babel/core");
        assert_eq!(identity.version, "7.24.0");
        assert_eq!(identity.identity(), "npm:@babel/core@7.24.0");
    }

    #[test]
    fn normalizes_cargo_identity() {
        let artifact = parse_identity("crates.io:My_Crate@1.0.0", None).unwrap();
        assert_eq!(artifact.ecosystem, Ecosystem::CratesIo);
        assert_eq!(artifact.name, "my_crate");
        assert_eq!(artifact.identity(), "crates.io:my_crate@1.0.0");
        assert_eq!(artifact.ecosystem.osv_name(), "crates.io");
    }

    #[test]
    fn normalizes_nuget_identity_and_version() {
        let artifact = parse_identity("nuget:Newtonsoft.Json@01.00.0.0-RC.1+build", None).unwrap();
        assert_eq!(artifact.identity(), "nuget:newtonsoft.json@1.0.0-rc.1");
    }

    #[test]
    fn rejects_invalid_nuget_identity_version_without_emptying_it() {
        assert_eq!(
            parse_package_identity("nuget:demo@not-a-version").unwrap_err(),
            ArtifactParseError::InvalidNugetVersion("not-a-version".to_string())
        );
        assert_eq!(
            Artifact::package(Ecosystem::Nuget, "demo", "not-a-version", None).version,
            "not-a-version"
        );
    }
}
