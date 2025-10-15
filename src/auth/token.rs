use crate::auth::core::{AuthInfo, TokenValidator};
use actix_web::error::ErrorUnauthorized;
use actix_web::Error;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub struct SimpleTokenAuthConfig {
    pub token_users_path: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct User {
    pub username: String,
    pub groups: Vec<String>,
    pub tokens: HashSet<String>,
}

impl User {
    pub fn new(username: &str, groups: Vec<&str>, tokens: Vec<&str>) -> User {
        User {
            username: username.to_string(),
            groups: groups.into_iter().map(|s| s.to_string()).collect(),
            tokens: tokens.into_iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SimpleTokenValidator {
    users: Arc<HashMap<String, User>>,
    token_to_user: Arc<HashMap<String, String>>, // token -> username mapping for quick lookup
}

impl SimpleTokenValidator {
    pub fn load(file_path: &str) -> Self {
        let file = std::fs::read_to_string(file_path).expect("Failed to read access rules file");
        let users = serde_yml::from_str(&file).expect("Failed to parse access rules file");
        Self::new(users)
    }
    pub fn new(users: Vec<User>) -> Self {
        let mut user_map = HashMap::new();
        let mut token_map = HashMap::new();

        for user in users {
            let username = user.username.clone();

            for token in &user.tokens {
                token_map.insert(token.clone(), username.clone());
            }

            user_map.insert(username, user);
        }

        Self {
            users: Arc::new(user_map),
            token_to_user: Arc::new(token_map),
        }
    }
}

impl TokenValidator for SimpleTokenValidator {
    fn validate_token<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AuthInfo, Error>> + Send + 'a>> {
        let token = token.to_string();
        let token_to_user = self.token_to_user.clone();
        let users = self.users.clone();

        Box::pin(async move {
            // Check if token exists in token map
            if let Some(username) = token_to_user.get(&token) {
                // Verify user exists
                if let Some(user) = users.get(username) {
                    // Return user information
                    Ok(AuthInfo {
                        username: user.username.clone(),
                        groups: user.groups.clone(),
                    })
                } else {
                    // Token mapped to non-existent user
                    Err(ErrorUnauthorized("Invalid user"))
                }
            } else {
                // Token not found
                Err(ErrorUnauthorized("Invalid token"))
            }
        })
    }
}
