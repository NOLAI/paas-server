use chrono::Utc;
use libpep::high_level::contexts::EncryptionContext;
use r2d2::{Pool, PooledConnection};
use rand::distributions::Alphanumeric;
use rand::Rng;
use redis::{Client, Commands};
use redis::{IntoConnectionInfo, RedisError};
use std::fmt::Error;
use std::io::{Error as ioError, ErrorKind};
use std::sync::Mutex;
use std::time::Duration;

pub trait SessionStorage: Send + Sync {
    fn start_session(&self, username: String) -> Result<String, Error>;
    fn end_session(&self, username: String, session_id: String) -> Result<(), Error>;
    fn get_sessions_for_user(&self, username: String) -> Result<Vec<EncryptionContext>, Error>;
    fn get_all_sessions(&self) -> Result<Vec<EncryptionContext>, Error>;
    fn session_exists(&self, username: String, session_id: String) -> Result<bool, Error>;
    fn clone_box(&self) -> Box<dyn SessionStorage>;
}
impl Clone for Box<dyn SessionStorage> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Clone)]
pub struct RedisSessionStorage {
    pool: Pool<Client>,
}

impl RedisSessionStorage {
    pub fn new<T: IntoConnectionInfo>(connection_info: T) -> Result<Self, RedisError> {
        let client = Client::open(connection_info)?;

        let pool = Pool::builder()
            .max_size(15) // Max number of connections
            .min_idle(Some(2)) // Min idle connections
            .max_lifetime(Some(Duration::from_secs(60 * 5))) // Max connection lifetime: 5 minutes
            .idle_timeout(Some(Duration::from_secs(60))) // Idle timeout: 1 minute
            .build(client)
            .map_err(|e| RedisError::from(ioError::new(ErrorKind::Other, e.to_string())))?;

        Ok(Self { pool })
    }
    fn get_connection(&self) -> Result<PooledConnection<Client>, Error> {
        self.pool.get().map_err(|_| Error)
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

        let _: () = redis::pipe()
            .set(&key, &session_time)
            .expire(&key, 86400) // 24 hours
            .query(&mut *connection)
            .map_err(|_| Error)?;

        Ok(session_id)
    }

    fn end_session(&self, username: String, session_id: String) -> Result<(), Error> {
        let mut connection = self.get_connection()?;

        let key = format!("sessions:{}:{}", username, session_id);
        let _: () = connection.del(key).expect("Failed to delete session");
        Ok(())
    }

    // TODO: Might need to be removed
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

    fn session_exists(&self, username: String, session_id: String) -> Result<bool, Error> {
        let mut conn = self.pool.get().map_err(|_| Error)?;
        let key = format!("sessions:{}:{}", username, session_id);

        let exists: bool = conn.exists(&key).map_err(|_| Error)?;
        Ok(exists)
    }

    fn clone_box(&self) -> Box<dyn SessionStorage> {
        Box::new((*self).clone())
    }
}

pub struct InMemorySessionStorage {
    sessions: Mutex<std::collections::HashMap<String, String>>,
}
impl Default for InMemorySessionStorage {
    fn default() -> Self {
        Self::new()
    }
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

    fn session_exists(&self, _username: String, session_id: String) -> Result<bool, Error> {
        let sessions = self.sessions.lock().unwrap();
        Ok(sessions.contains_key(&session_id))
    }

    fn clone_box(&self) -> Box<dyn SessionStorage> {
        Box::new(Self {
            sessions: Mutex::new(self.sessions.lock().unwrap().clone()),
        })
    }
}
