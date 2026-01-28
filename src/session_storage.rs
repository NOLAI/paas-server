use chrono::{TimeZone, Utc};
use libpep::factors::EncryptionContext;
use r2d2::{Pool, PooledConnection};
use rand::distr::Alphanumeric;
use rand::Rng;
use redis::{Client, Commands};
use redis::{IntoConnectionInfo, RedisError};
use std::fmt::Error;
use std::io::Error as ioError;
use std::sync::{Arc, Mutex};
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
pub struct RedisOptions {
    pub max_pool_size: u32,
    pub min_idle: Option<u32>,
    pub max_lifetime: Option<Duration>,
    pub connection_timeout: Option<Duration>,
}

impl Default for RedisOptions {
    fn default() -> Self {
        Self {
            max_pool_size: 15,
            min_idle: Some(2),
            max_lifetime: Some(Duration::from_secs(300)),
            connection_timeout: Some(Duration::from_secs(60)),
        }
    }
}

#[derive(Clone)]
pub struct RedisSessionStorage {
    pool: Pool<Client>,
    session_expiry: Duration,
    new_session_length: usize,
}

impl RedisSessionStorage {
    pub fn new<T: IntoConnectionInfo>(
        connection_info: T,
        session_expiry: Duration,
        new_session_length: usize,
        options: RedisOptions,
    ) -> Result<Self, RedisError> {
        let client = Client::open(connection_info)?;

        let pool = Pool::builder()
            .max_size(options.max_pool_size)
            .min_idle(options.min_idle)
            .max_lifetime(options.max_lifetime)
            .idle_timeout(options.connection_timeout)
            .build(client)
            .map_err(|e| RedisError::from(ioError::other(e.to_string())))?;

        Ok(Self {
            pool,
            session_expiry,
            new_session_length,
        })
    }

    fn get_connection(&self) -> Result<PooledConnection<Client>, Error> {
        self.pool.get().map_err(|_| Error)
    }
}

impl SessionStorage for RedisSessionStorage {
    fn start_session(&self, username: String) -> Result<String, Error> {
        // Generate a random string for the session ID
        let session_postfix: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(self.new_session_length) // Random string length
            .map(char::from)
            .collect();

        let session_time = Utc::now().timestamp();

        let session_id = format!("{}_{}", username, session_postfix);
        let key = format!("sessions:{}:{}", username, session_id);

        let mut connection = self.get_connection()?;

        let _: () = redis::pipe()
            .set(&key, session_time)
            .expire(&key, self.session_expiry.as_secs() as i64) // 1 hour
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

        // Check if the session_id already contains the username prefix
        let actual_session_id = if session_id.starts_with(&format!("{}_", username)) {
            // If it already has the prefix, use as is
            session_id
        } else {
            // Add the prefix if it doesn't already have it
            format!("{}_{}", username, session_id)
        };

        let key = format!("sessions:{}:{}", username, actual_session_id);

        let exists: bool = conn.exists(&key).map_err(|_| Error)?;
        Ok(exists)
    }

    fn clone_box(&self) -> Box<dyn SessionStorage> {
        Box::new((*self).clone())
    }
}

#[derive(Clone)]
pub struct InMemorySessionStorage {
    sessions: Arc<Mutex<std::collections::HashMap<String, String>>>,
    session_expiry: Duration,
    new_session_length: usize,
}

impl InMemorySessionStorage {
    pub fn new(session_expiry: Duration, new_session_length: usize) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
            session_expiry,
            new_session_length,
        }
    }
    fn is_session_expired(&self, timestamp_str: &str) -> Result<bool, Error> {
        let timestamp = timestamp_str.parse::<i64>().map_err(|_| Error)?;
        let session_time = Utc.timestamp_opt(timestamp, 0).single().ok_or(Error)?;

        let now = Utc::now();
        let expiry_time = session_time + self.session_expiry;

        Ok(now > expiry_time)
    }

    fn clean_expired_sessions(&self) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().map_err(|_| Error)?;
        let mut expired_keys = Vec::new();

        for (key, time_str) in sessions.iter() {
            if self.is_session_expired(time_str)? {
                expired_keys.push(key.clone());
            }
        }

        for key in expired_keys {
            sessions.remove(&key);
        }
        Ok(())
    }
}

impl SessionStorage for InMemorySessionStorage {
    fn start_session(&self, username: String) -> Result<String, Error> {
        let session_postfix: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(self.new_session_length) // Random string length
            .map(char::from)
            .collect();

        let session_id = format!("{}_{}", username, session_postfix);

        let session_time = Utc::now().timestamp();
        self.sessions
            .lock()
            .map_err(|_| Error)?
            .insert(session_id.clone(), session_time.to_string());
        Ok(session_id)
    }

    fn end_session(&self, username: String, session_id: String) -> Result<(), Error> {
        let session_id = format!("{}_{}", username, session_id);
        let mut sessions = self.sessions.lock().map_err(|_| Error)?;
        sessions.remove(&session_id);
        Ok(())
    }

    fn get_sessions_for_user(&self, username: String) -> Result<Vec<EncryptionContext>, Error> {
        self.clean_expired_sessions()?;

        let sessions = self.sessions.lock().map_err(|_| Error)?;
        let sessions: Vec<EncryptionContext> = sessions
            .iter()
            .filter(|(session_id, _)| session_id.starts_with(&username))
            .map(|(session_id, _)| EncryptionContext::from(session_id))
            .collect();
        Ok(sessions)
    }

    fn get_all_sessions(&self) -> Result<Vec<EncryptionContext>, Error> {
        self.clean_expired_sessions()?;

        let sessions = self.sessions.lock().map_err(|_| Error)?;
        let sessions: Vec<EncryptionContext> = sessions
            .keys()
            .map(|session_id| EncryptionContext::from(session_id))
            .collect();
        Ok(sessions)
    }

    fn session_exists(&self, username: String, session_id: String) -> Result<bool, Error> {
        self.clean_expired_sessions()?;

        // Check if the session_id already contains the username prefix
        let key = if session_id.starts_with(&format!("{}_", username)) {
            session_id
        } else {
            // Add the prefix if it doesn't already have it
            format!("{}_{}", username, session_id)
        };

        let sessions = self.sessions.lock().map_err(|_| Error)?;
        Ok(sessions.contains_key(&key))
    }

    fn clone_box(&self) -> Box<dyn SessionStorage> {
        Box::new(self.clone())
    }
}
