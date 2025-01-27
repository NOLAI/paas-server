use chrono::{DateTime, Utc};
use libpep::high_level::contexts::PseudonymizationContext;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;

pub type Usergroup = String;

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub username: Arc<String>,
    pub usergroups: Arc<HashSet<Usergroup>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Permission {
    pub usergroups: Vec<Usergroup>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub from: Vec<PseudonymizationContext>,
    pub to: Vec<PseudonymizationContext>,
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
        authentication_info: &AuthenticatedUser,
        from: &PseudonymizationContext,
        to: &PseudonymizationContext,
    ) -> bool {
        for permission in self.get_currently_valid_permissions() {
            if permission
                .usergroups
                .iter()
                .any(|group| authentication_info.usergroups.contains(group))
                && permission.from.iter().any(|context| context == from)
                && permission.to.iter().any(|context| context == to)
            {
                return true;
            }
        }
        false
    }
}
