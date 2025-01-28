use libpep::distributed::key_blinding::SessionKeyShare;
use libpep::high_level::contexts::EncryptionContext;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct GetSessionsRequest {
    pub username: Option<EncryptionContext>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct GetSessionResponse {
    pub sessions: Vec<EncryptionContext>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StartSessionResponse {
    pub session_id: EncryptionContext,
    pub key_share: SessionKeyShare,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EndSessionRequest {
    pub session_id: EncryptionContext,
}
