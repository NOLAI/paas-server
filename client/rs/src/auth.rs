use crate::transcryptor_client::AuthToken;
use paas_common::status::SystemId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens(pub HashMap<SystemId, AuthToken>);

impl AuthTokens {
    pub fn get(&self, system_id: &SystemId) -> Option<&AuthToken> {
        self.0.get(system_id)
    }
}
