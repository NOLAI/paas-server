use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::ErrorUnauthorized;
use actix_web::{Error, HttpMessage};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Arc;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct AllowConfig {
    pub allow: Vec<Permission>,
}

pub type Domain = String;
pub type Usergroup = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct Permission {
    pub name: String,
    pub usergroups: Vec<Usergroup>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub from: Vec<Domain>,
    pub to: Vec<Domain>,
}

#[derive(Clone)]
pub struct AuthMiddleware {
    decoding_key: Arc<DecodingKey>,
    allow_config: Arc<AllowConfig>,
}

pub fn filter_on_usergroup(allow_config: &AllowConfig, groups_of_user: Vec<Usergroup>) -> (Vec<Domain>, Vec<Domain>) {
    let mut from: HashSet<Domain> = HashSet::new();
    let mut to: HashSet<Domain> = HashSet::new();

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
    pub from: Arc<Vec<Domain>>,
    pub to: Arc<Vec<Domain>>,
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
    name: String, // For logs
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
        println!("{:?}", decode::<Claims
        >("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsIm5hbWUiOiJKb2huIERvZSIsImdyb3VwcyI6WyJwcm9qZWN0MS1jb29yZGluYXRvciIsInByb2plY3QxLWFuYWx5c3QiXSwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOiIxOTIzMzE0NjM3In0.qRR3pUqFl4jPLjfnodGL3uTq0vg5y7oRBZBCnhOSa1rKFB_dHyeYQfztem22Xv5ziSyUCz1tx2jDnsqfDjCTJSK9stSz8qqwQW58TF7X7BRv31oe7R9UH8_cFXsHgW5VLrugzSyxh5vtUsL7wBQVOwXoksQAGFEBoms80RFvyQWm-W7LRSNLIQQlSBABJvPCb82jUsx4Yz6XLKf61e64HLX2U9VBGLt7g_Ga_GSVGII_bmJ1y86DUTIw2aaKIzG4pgEDCCYr-ufHZB16WTLvkII01DcuGdj5xQg17mNtfCzdVdeIkjbLj03blclgIaqsFul8lMKZuTx_jIds93nVq6h4eu_CpC9_bR_nAHhLiiyt54C-Ttj8qjoaBVSL7F_eI2wQexX_OkABUPPriVhW-LNTSqUB1YKhoAJ3M5DIA-pfCQuAJxhWCNW34YakBZdDp3jbpiQI-Ve9IjOifAEuCe_LzH0kyWGejY8WBcwpp6u7UJMDbrKWmYVw5b9T4kLDTFWQeFiZ_qTTwe1GI-uvh2eCWekog8rgp0qrVYPOL-fgOSeEGHD0r5Oa2I-624FcsEkFFKzTAuZxikJr9Vh_C4b7tggahUPm6Ym3noZay3Oq58QBb5Sq6-IdnJkwTlzHVm0pY5XORp90-SzcDdfiU6Qw0XJt_oFyD2s5bB3HjVw", self.decoding_key.borrow(), &Validation::new(Algorithm::RS256)));

        println!("{:?}", token_data);

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

        Box::pin(async move { Err(ErrorUnauthorized("Unauthorized")) }) // TODO check actix-extras#260 to give correct CORS headers on error
    }
}
