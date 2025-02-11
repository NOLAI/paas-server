use libpep::distributed::key_blinding::SessionKeyShare;
use libpep::high_level::contexts::EncryptionContext;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
/// Get all current open sessions (for a user).
pub struct GetSessionsRequest {
    pub username: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
/// Return all current sessions.
pub struct GetSessionResponse {
    pub sessions: Vec<EncryptionContext>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Start a new PEP session
pub struct StartSessionResponse {
    /// A session id
    pub session_id: EncryptionContext,
    /// The secret session key share for this session. Will be provided just once.
    pub key_share: SessionKeyShare,
}

#[derive(Serialize, Deserialize, Debug)]
/// Terminate a session
pub struct EndSessionRequest {
    pub session_id: EncryptionContext,
}
