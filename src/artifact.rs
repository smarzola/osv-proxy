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
}

impl Ecosystem {
    pub fn normalize_name(self, name: &str) -> String {
        match self {
            Ecosystem::Npm => name.to_string(),
            Ecosystem::Pypi => normalize_pypi_name(name),
        }
    }

    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "PyPI",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::Pypi => write!(f, "pypi"),
        }
    }
}

impl FromStr for Ecosystem {
    type Err = ArtifactParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "npm" => Ok(Ecosystem::Npm),
            "pypi" | "python" | "python-package" => Ok(Ecosystem::Pypi),
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
    Ok(Artifact::package(ecosystem, name, version, published_at))
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactParseError {
    #[error("unsupported ecosystem: {0}")]
    UnsupportedEcosystem(String),
    #[error("expected package identity in the form ecosystem:name@version: {0}")]
    InvalidIdentity(String),
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
}
