use actix_web::{Error, HttpMessage};
use actix_web::error::{ErrorUnauthorized};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::collections::HashMap;
use std::sync::Arc;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TokenConfig {
    tokens: HashMap<String, String>,
}

#[derive(Clone)]
pub struct AuthMiddleware {
    tokens: Arc<HashMap<String, String>>,
}

#[derive(Clone, Debug)]
pub struct AuthenticationInfo {
    pub username: Arc<String>,
}

impl AuthMiddleware {
    pub fn new(token_file: &str) -> Self {
        let file_content = fs::read_to_string(token_file)
            .expect("Failed to read token file");
        let token_config: TokenConfig = serde_yml::from_str(&file_content)
            .expect("Failed to parse token file");
        AuthMiddleware { 
            tokens: Arc::new(token_config.tokens),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareService {
            service,
            tokens: Arc::clone(&self.tokens),
        })
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
    tokens: Arc<HashMap<String, String>>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let token = req.headers().get("Authorization").and_then(|header| header.to_str().ok());

        if let Some(token) = token {
            for (user, user_token) in self.tokens.iter() {
                if user_token == token.trim_start_matches("Bearer ") {
                    let found_user = user.clone();
                    println!("Found user: {}", found_user); // TODO: Should be logged or removed
                    req.extensions_mut().insert::<AuthenticationInfo>({
                        AuthenticationInfo {
                            username: Arc::new(found_user),
                        }});
                    let fut = self.service.call(req);
                    return Box::pin(async move {
                        let res = fut.await?;
                        Ok(res)
                    });
                };
            }
        }

        Box::pin(async move { Err(ErrorUnauthorized("Unauthorized")) })
    }
}
