use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage};
use actix_web::error::ErrorUnauthorized;
use futures_util::future::{ok, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Borrow;
use std::collections::{ HashSet};
use std::fs;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use libpep::high_level::contexts::PseudonymizationContext;

#[derive(Debug, Serialize, Deserialize)]
pub struct AllowConfig {
    pub allow: Vec<Permission>,
}

pub type Usergroup = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct Permission {
    pub usergroups: Vec<Usergroup>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub from: Vec<PseudonymizationContext>,
    pub to: Vec<PseudonymizationContext>,
}

#[derive(Clone)]
pub struct AuthMiddleware {
    decoding_key: Arc<DecodingKey>,
    allow_config: Arc<AllowConfig>,
}

pub fn filter_on_usergroup(allow_config: &AllowConfig, groups_of_user: Vec<Usergroup>) -> (Vec<PseudonymizationContext>, Vec<PseudonymizationContext>) {
    let mut from: HashSet<PseudonymizationContext> = HashSet::new();
    let mut to: HashSet<PseudonymizationContext> = HashSet::new();

    for permission in &allow_config.allow {
        if permission.start.is_some() && permission.start.unwrap() > Utc::now() || permission.end.is_some() && permission.end.unwrap() < Utc::now() {
            continue;
        }
        if permission.usergroups.iter().any(|x| groups_of_user.contains(x)) {
            from.extend(permission.from.clone());
            to.extend(permission.to.clone());
        }
    }

    (from.into_iter().collect(), to.into_iter().collect())
}
#[derive(Clone, Debug)]
pub struct AuthenticationInfo {
    pub username: Arc<String>,
}

#[derive(Clone, Debug)]
pub struct DomainInfo {
    pub from: Arc<Vec<PseudonymizationContext>>,
    pub to: Arc<Vec<PseudonymizationContext>>,
}

impl AuthMiddleware {
    pub fn new(token_file: &str, allow_file: &str) -> Self {
        let toke_file_content = fs::read_to_string(token_file).expect("Failed to read token file");
        let allow_file_content = fs::read_to_string(allow_file).expect("Failed to read allow file");
        let allow_config: AllowConfig = serde_yaml::from_str(&allow_file_content).expect("Failed to parse allow file");
        let decoding_key = DecodingKey::from_rsa_pem(toke_file_content.as_bytes())
            .expect("Failed to use provided public key for JWTs");
        AuthMiddleware {
            decoding_key: Arc::new(decoding_key),
            allow_config: Arc::new(allow_config),
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
            decoding_key: Arc::clone(&self.decoding_key),
            allow_config: Arc::clone(&self.allow_config),
        })
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
    decoding_key: Arc<DecodingKey>,
    allow_config: Arc<AllowConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    groups: Vec<String>,
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
        let len = "bearer ".len();
        let token_data=  req
            .headers()
            .get("Authorization")
            .and_then(|header| header.to_str().ok())
            .and_then(|hv| Some(&hv[len..]))
            .and_then(|token|
                decode::<Claims>(
                    token,
                    self.decoding_key.borrow(),
                    &Validation::new(Algorithm::RS256),
                ).ok()
            );
        // .and_then(|f| Some(f.claims.sub));
        
        if let Some(data) = token_data {
            let found_user = data.claims.sub;
            req.extensions_mut().insert::<AuthenticationInfo>({
                AuthenticationInfo {
                    username: Arc::new(found_user),
                }
            });

            let (from, to) = filter_on_usergroup(&self.allow_config, data.claims.groups.clone());
            req.extensions_mut().insert(DomainInfo {
                from: Arc::new(from),
                to: Arc::new(to),
            });
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            });
        }

        Box::pin(async {
            Err(ErrorUnauthorized("Unauthorized"))
        })
    }
}
