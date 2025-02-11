use crate::{CURRENT_PROTOCOL_VERSION, MIN_SUPPORTED_VERSION};
use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};

fn default_protocol_version() -> Version {
    Version::parse(CURRENT_PROTOCOL_VERSION).expect("Invalid CURRENT_PROTOCOL_VERSION")
}
fn default_min_version() -> Version {
    Version::parse(MIN_SUPPORTED_VERSION).expect("Invalid MIN_SUPPORTED_VERSION")
}
#[derive(Serialize, Deserialize, Debug)]
pub struct VersionInfo {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: Version,
    #[serde(default = "default_min_version")]
    pub min_supported_version: Version,
}
impl Default for VersionInfo {
    fn default() -> Self {
        Self {
            protocol_version: default_protocol_version(),
            min_supported_version: default_min_version(),
        }
    }
}
impl VersionInfo {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_compatible_with(&self, other: &VersionInfo) -> bool {
        self.protocol_version >= other.min_supported_version
            && other.protocol_version >= self.min_supported_version
    }
}

pub type SystemId = String;

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusResponse {
    pub system_id: SystemId,
    pub timestamp: DateTime<Utc>,
    pub version_info: VersionInfo,
}
