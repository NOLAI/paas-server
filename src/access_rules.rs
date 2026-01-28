use crate::auth::core::AuthInfo;
use chrono::{DateTime, Utc};
use libpep::factors::PseudonymizationDomain;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Permission {
    pub usergroups: Vec<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub from: Vec<PseudonymizationDomain>,
    pub to: Vec<PseudonymizationDomain>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessRules {
    pub allow: Vec<Permission>,
}
impl AccessRules {
    pub fn load(file_path: &str) -> Self {
        let file = std::fs::read_to_string(file_path).expect("Failed to read access rules file");
        serde_yml::from_str(&file).expect("Failed to parse access rules file")
    }
    fn get_currently_valid_permissions(&self) -> Vec<&Permission> {
        self.allow
            .iter()
            .filter(|permission| {
                if let Some(start) = permission.start {
                    if start > Utc::now() {
                        return false;
                    }
                }
                if let Some(end) = permission.end {
                    if end < Utc::now() {
                        return false;
                    }
                }
                true
            })
            .collect()
    }
    pub fn has_access(
        &self,
        authentication_info: &AuthInfo,
        from: &PseudonymizationDomain,
        to: &PseudonymizationDomain,
    ) -> bool {
        for permission in self.get_currently_valid_permissions() {
            if permission
                .usergroups
                .iter()
                .any(|group| authentication_info.groups.contains(group))
                && permission.from.iter().any(|context| context == from)
                && permission.to.iter().any(|context| context == to)
            {
                return true;
            }
        }
        false
    }
}
