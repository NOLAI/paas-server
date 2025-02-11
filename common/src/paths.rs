pub const API_BASE: &str = ""; // Currently empty (may need to change)

pub const STATUS: &str = "/status";
pub mod sessions {
    pub const SCOPE: &str = "/sessions";
    pub const GET_ALL: &str = "/get";
    pub const GET_USER: &str = "/get/{username}";
    pub const START: &str = "/start";
    pub const END: &str = "/end";
}

pub mod transcrypt {
    pub const PSEUDONYMIZE: &str = "/pseudonymize";
    pub const PSEUDONYMIZE_BATCH: &str = "/pseudonymize_batch";
    pub const REKEY: &str = "/rekey";
}
