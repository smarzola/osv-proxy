use crate::artifact::{Artifact, Ecosystem};
use chrono::{DateTime, Utc};

pub fn package_artifact(
    name: impl AsRef<str>,
    version: impl Into<String>,
    published_at: Option<DateTime<Utc>>,
) -> Artifact {
    Artifact::package(Ecosystem::Npm, name, version, published_at)
}
