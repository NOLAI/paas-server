use chrono::{TimeZone, Utc};
use libpep::contexts::EncryptionContext;
use r2d2::{Pool, PooledConnection};
use rand::distr::Alphanumeric;
use rand::RngExt;
use redis::{Client, Commands};
use redis::{IntoConnectionInfo, RedisError};
use std::fmt::Error;
use std::io::Error as ioError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub trait SessionStorage: Send + Sync {
    fn start_session(&self, username: String) -> Result<String, Error>;
    fn end_session(&self, username: String, session_id: EncryptionContext) -> Result<(), Error>;
    fn get_sessions_for_user(&self, username: String) -> Result<Vec<EncryptionContext>, Error>;
    fn session_exists(
        &self,
        username: String,
        session_id: EncryptionContext,
    ) -> Result<bool, Error>;
    /// Bounded (O(1)) connectivity probe. Must never scan the keyspace, as it is
    /// reachable from the unauthenticated health endpoint.
    fn is_healthy(&self) -> Result<(), Error>;
    fn clone_box(&self) -> Box<dyn SessionStorage>;
}

impl Clone for Box<dyn SessionStorage> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

pub trait ToSessionKey {
    fn to_key_string(&self) -> Result<String, Error>;
}

/// Returns whether `session_id` has the exact shape `{username}_{postfix}`, where the
/// postfix is the alphanumeric random part. Anchoring on the full `{username}_` prefix
/// and rejecting further `_` in the postfix prevents user `al` from matching sessions of
/// users like `alice` or `al_x`.
pub fn is_session_of(session_id: &str, username: &str) -> bool {
    session_id
        .strip_prefix(username)
        .and_then(|rest| rest.strip_prefix('_'))
        .is_some_and(|postfix| {
            !postfix.is_empty() && postfix.chars().all(|c| c.is_ascii_alphanumeric())
        })
}

/// Resolves a client-supplied session id to the full `{username}_{postfix}` form,
/// accepting either the full id or just the postfix.
fn full_session_id(username: &str, session_id: &str) -> String {
    if is_session_of(session_id, username) {
        session_id.to_string()
    } else {
        format!("{}_{}", username, session_id)
    }
}

/// Escapes Redis glob metacharacters so a username is matched literally.
fn escape_redis_glob(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

impl ToSessionKey for EncryptionContext {
    fn to_key_string(&self) -> Result<String, Error> {
        match self {
            EncryptionContext::Specific(s) => Ok(s.clone()),
            EncryptionContext::Global => Err(Error),
        }
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

    fn end_session(&self, username: String, session_id: EncryptionContext) -> Result<(), Error> {
        let session_id = full_session_id(&username, &session_id.to_key_string()?);
        let key = format!("sessions:{}:{}", username, session_id);

        let mut connection = self.get_connection()?;
        let _: () = connection.del(key).map_err(|_| Error)?;
        Ok(())
    }

    fn get_sessions_for_user(&self, username: String) -> Result<Vec<EncryptionContext>, Error> {
        let mut connection = self.get_connection()?;

        // SCAN instead of KEYS so large keyspaces don't block Redis
        let pattern = format!("sessions:{}:*", escape_redis_glob(&username));
        let prefix = format!("sessions:{}:", username);
        let sessions: Vec<EncryptionContext> = connection
            .scan_match::<_, String>(pattern)
            .map_err(|_| Error)?
            .filter_map(|key| key.ok())
            .filter_map(|key| key.strip_prefix(&prefix).map(str::to_string))
            .filter(|session_id| is_session_of(session_id, &username))
            .map(|session_id| EncryptionContext::from(&session_id))
            .collect();
        Ok(sessions)
    }

    fn session_exists(
        &self,
        username: String,
        session_id: EncryptionContext,
    ) -> Result<bool, Error> {
        let session_id = full_session_id(&username, &session_id.to_key_string()?);
        let key = format!("sessions:{}:{}", username, session_id);

        let mut connection = self.get_connection()?;
        let exists: bool = connection.exists(&key).map_err(|_| Error)?;
        Ok(exists)
    }

    fn is_healthy(&self) -> Result<(), Error> {
        let mut connection = self.get_connection()?;
        redis::cmd("PING")
            .query::<String>(&mut *connection)
            .map_err(|_| Error)?;
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn SessionStorage> {
        Box::new((*self).clone())
    }
}

/// Sessions keyed by username, then by full session id, mapping to the start timestamp.
/// Namespacing by username (like the Redis `sessions:{username}:{id}` keys) guarantees
/// lookups can never cross user boundaries.
type UserSessions = std::collections::HashMap<String, std::collections::HashMap<String, i64>>;

#[derive(Clone)]
pub struct InMemorySessionStorage {
    sessions: Arc<Mutex<UserSessions>>,
    session_expiry: Duration,
    new_session_length: usize,
}

impl InMemorySessionStorage {
    pub fn new(session_expiry: Duration, new_session_length: usize) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(UserSessions::new())),
            session_expiry,
            new_session_length,
        }
    }

    fn is_session_expired(&self, timestamp: i64) -> bool {
        Utc.timestamp_opt(timestamp, 0)
            .single()
            .is_none_or(|session_time| Utc::now() > session_time + self.session_expiry)
    }

    fn clean_expired_sessions(&self, sessions: &mut UserSessions) {
        sessions.retain(|_, user_sessions| {
            user_sessions.retain(|_, timestamp| !self.is_session_expired(*timestamp));
            !user_sessions.is_empty()
        });
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
            .entry(username)
            .or_default()
            .insert(session_id.clone(), session_time);
        Ok(session_id)
    }

    fn end_session(&self, username: String, session_id: EncryptionContext) -> Result<(), Error> {
        let session_id = full_session_id(&username, &session_id.to_key_string()?);
        let mut sessions = self.sessions.lock().map_err(|_| Error)?;
        if let Some(user_sessions) = sessions.get_mut(&username) {
            user_sessions.remove(&session_id);
            if user_sessions.is_empty() {
                sessions.remove(&username);
            }
        }
        Ok(())
    }

    fn get_sessions_for_user(&self, username: String) -> Result<Vec<EncryptionContext>, Error> {
        let mut sessions = self.sessions.lock().map_err(|_| Error)?;
        self.clean_expired_sessions(&mut sessions);

        Ok(sessions
            .get(&username)
            .map(|user_sessions| {
                user_sessions
                    .keys()
                    .map(|id| EncryptionContext::from(id.as_str()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn session_exists(
        &self,
        username: String,
        session_id: EncryptionContext,
    ) -> Result<bool, Error> {
        let session_id = full_session_id(&username, &session_id.to_key_string()?);

        let mut sessions = self.sessions.lock().map_err(|_| Error)?;
        self.clean_expired_sessions(&mut sessions);

        Ok(sessions
            .get(&username)
            .is_some_and(|user_sessions| user_sessions.contains_key(&session_id)))
    }

    fn is_healthy(&self) -> Result<(), Error> {
        // Only verifies the mutex isn't poisoned; never walks the session map
        self.sessions.lock().map(|_| ()).map_err(|_| Error)
    }

    fn clone_box(&self) -> Box<dyn SessionStorage> {
        Box::new(self.clone())
    }
}
