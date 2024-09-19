use std::{env};
use redis::{Client, Commands};
use redis::RedisError;
use chrono::Utc;
use rand::distributions::Alphanumeric;
use rand::Rng;

#[derive(Clone)]
pub struct RedisConnector {
    client: Client
}

impl RedisConnector {
    pub fn new() -> Result<RedisConnector, RedisError> {
        let client = Client::open(env::var("REDIS_URL").unwrap())?;
        Ok(RedisConnector { client })
    }

    pub fn start_session(&mut self, username: String) -> Result<String, RedisError> {
        // Generate a random string for the session ID
        let session_postfix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10) // Random string length
            .map(char::from)
            .collect();
        
        let session_time = Utc::now().format("%Y%m%d_%H").to_string();

        let session_id = format!("{}_{}", username, session_postfix);
        let key = format!("sessions:{}:{}", username, session_id);

        let mut connection = self.client.get_connection()?;

        let _: () = connection.set(key.clone(), session_time).expect("Failed to set session data");
        // Set expiration for 24 hours
        let _: () = connection.expire(key.clone(), 86400).expect("Failed to set expiration");
        
        Ok(session_id)
    }
    
    pub fn end_session(&mut self, username: String, session_id: String) -> Result<(), RedisError> {
        let mut connection = self.client.get_connection()?;
        
        let key = format!("sessions:{}:{}", username, session_id);
        let _: () = connection.del(key).expect("Failed to delete session");
        Ok(())
    }
    
    pub fn get_sessions_for_user(&mut self, username: String) -> Result<Vec<String>, RedisError> {
        let mut connection = self.client.get_connection()?;

        let key = format!("sessions:{}:*", username);
        let keys: Vec<String> = connection.keys(key).expect("Failed to get keys");
        let sessions: Vec<String> = keys.iter().map(|key| {
            key.split(":").collect::<Vec<&str>>()[2].to_string()
        }).collect();
        Ok(sessions)
    }
}