use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage};
use actix_web::error::ErrorUnauthorized;
use futures_util::future::{ok, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Borrow;
use std::fs;
use std::sync::Arc;
use crate::access_rules::AuthenticatedUser;

#[derive(Clone)]
pub struct JWTAuthMiddleware {
    jwt_key: Arc<DecodingKey>,
}

impl JWTAuthMiddleware {
    pub fn new(jwt_key_file: &str) -> Self {
        let jwt_key_file_content = fs::read_to_string(jwt_key_file).expect("Failed to read token file");
        let jwt_key = DecodingKey::from_rsa_pem(jwt_key_file_content.as_bytes())
            .expect("Failed to use provided public key for JWTs");
        JWTAuthMiddleware {
            jwt_key: Arc::new(jwt_key),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JWTAuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JWTAuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JWTAuthMiddlewareService {
            service,
            jwt_key: Arc::clone(&self.jwt_key),
        })
    }
}

pub struct JWTAuthMiddlewareService<S> {
    service: S,
    jwt_key: Arc<DecodingKey>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    groups: Vec<String>,
}

impl<S, B> Service<ServiceRequest> for JWTAuthMiddlewareService<S>
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
        let len = "bearer ".len();
        let token_data=  req
            .headers()
            .get("Authorization")
            .and_then(|header| header.to_str().ok())
            .and_then(|hv| Some(&hv[len..]))
            .and_then(|token|
                decode::<Claims>(
                    token,
                    self.jwt_key.borrow(),
                    &Validation::new(Algorithm::RS256),
                ).ok()
            );

        if token_data.is_none() {
            return Box::pin(async {
                Err(ErrorUnauthorized("Invalid JWT"))
            });
        }

        let data = token_data.unwrap();
        req.extensions_mut().insert::<AuthenticatedUser>({
            AuthenticatedUser {
                username: Arc::new(data.claims.sub),
                usergroups: Arc::new(data.claims.groups.into_iter().collect()),
            }
        });

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}
