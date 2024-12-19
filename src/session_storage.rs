use chrono::Utc;
use libpep::high_level::contexts::EncryptionContext;
use rand::distributions::Alphanumeric;
use rand::Rng;
use redis::{Client, Commands};
use redis::{Connection, IntoConnectionInfo, RedisError};
use std::fmt::Error;
use std::sync::Mutex;

pub trait SessionStorage: Send + Sync {
    fn start_session(&self, username: String) -> Result<String, Error>;
    fn end_session(&self, username: String, session_id: String) -> Result<(), Error>;
    fn get_sessions_for_user(&self, username: String) -> Result<Vec<EncryptionContext>, Error>;
    fn get_all_sessions(&self) -> Result<Vec<EncryptionContext>, Error>;
    fn clone_box(&self) -> Box<dyn SessionStorage>;
}
impl Clone for Box<dyn SessionStorage> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Clone)]
pub struct RedisSessionStorage {
    client: Client,
}

impl RedisSessionStorage {
    pub fn new<T: IntoConnectionInfo>(connection_info: T) -> Result<Self, RedisError> {
        let client = Client::open(connection_info)?;
        Ok(Self { client })
    }
    fn get_connection(&self) -> Result<Connection, Error> {
        self.client.get_connection().map_err(|_| Error)
    }
}
impl SessionStorage for RedisSessionStorage {
    fn start_session(&self, username: String) -> Result<String, Error> {
        // Generate a random string for the session ID
        let session_postfix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10) // Random string length
            .map(char::from)
            .collect();

        let session_time = Utc::now().format("%Y%m%d_%H").to_string();

        let session_id = format!("{}_{}", username, session_postfix);
        let key = format!("sessions:{}:{}", username, session_id);

        let mut connection = self.get_connection()?;

        let _: () = connection
            .set(key.clone(), session_time)
            .expect("Failed to set session data");
        // Set expiration for 24 hours
        let _: () = connection
            .expire(key.clone(), 86400)
            .expect("Failed to set expiration");

        Ok(session_id)
    }

    fn end_session(&self, username: String, session_id: String) -> Result<(), Error> {
        let mut connection = self.get_connection()?;

        let key = format!("sessions:{}:{}", username, session_id);
        let _: () = connection.del(key).expect("Failed to delete session");
        Ok(())
    }

    fn get_sessions_for_user(&self, username: String) -> Result<Vec<EncryptionContext>, Error> {
        let mut connection = self.get_connection()?;

        let key = format!("sessions:{}:*", username);
        let keys: Vec<String> = connection.keys(key).expect("Failed to get keys");
        let sessions: Vec<EncryptionContext> = keys
            .iter()
            .map(|key| key.split(":").collect::<Vec<&str>>()[2].to_string())
            .map(|session_id| EncryptionContext::from(&session_id))
            .collect();
        Ok(sessions)
    }
    fn get_all_sessions(&self) -> Result<Vec<EncryptionContext>, Error> {
        let mut connection = self.get_connection()?;

        let keys: Vec<String> = connection.keys("sessions:*:*").expect("Failed to get keys");
        let sessions: Vec<EncryptionContext> = keys
            .iter()
            .map(|key| key.split(":").collect::<Vec<&str>>()[2].to_string())
            .map(|session_id| EncryptionContext::from(&session_id))
            .collect();
        Ok(sessions)
    }

    fn clone_box(&self) -> Box<dyn SessionStorage> {
        Box::new((*self).clone())
    }
}

pub struct InMemorySessionStorage {
    sessions: Mutex<std::collections::HashMap<String, String>>,
}
impl InMemorySessionStorage {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(std::collections::HashMap::new()),
        }
    }
}
impl SessionStorage for InMemorySessionStorage {
    fn start_session(&self, username: String) -> Result<String, Error> {
        let session_postfix: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10) // Random string length
            .map(char::from)
            .collect();

        let session_time = Utc::now().format("%Y%m%d_%H").to_string();

        let session_id = format!("{}_{}", username, session_postfix);
        self.sessions
            .lock()
            .unwrap()
            .insert(session_id.clone(), session_time);
        Ok(session_id)
    }

    fn end_session(&self, username: String, session_id: String) -> Result<(), Error> {
        let session_id = format!("{}_{}", username, session_id);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(&session_id);
        Ok(())
    }

    fn get_sessions_for_user(&self, username: String) -> Result<Vec<EncryptionContext>, Error> {
        let sessions = self.sessions.lock().unwrap();
        let sessions: Vec<EncryptionContext> = sessions
            .iter()
            .filter(|(session_id, _)| session_id.starts_with(&username))
            .map(|(session_id, _)| EncryptionContext::from(session_id))
            .collect();
        Ok(sessions)
    }

    fn get_all_sessions(&self) -> Result<Vec<EncryptionContext>, Error> {
        let sessions = self.sessions.lock().unwrap();
        let sessions: Vec<EncryptionContext> = sessions
            .keys()
            .map(|session_id| EncryptionContext::from(session_id))
            .collect();
        Ok(sessions)
    }

    fn clone_box(&self) -> Box<dyn SessionStorage> {
        Box::new(Self {
            sessions: Mutex::new(self.sessions.lock().unwrap().clone()),
        })
    }
}
