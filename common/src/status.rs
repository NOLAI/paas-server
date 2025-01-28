use serde::{Deserialize, Serialize};

pub type SystemId = String;

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusResponse {
    pub system_id: SystemId,
    pub timestamp: String,
}
