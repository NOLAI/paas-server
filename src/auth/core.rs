use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized,
    Error, FromRequest, HttpMessage,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use futures::future::{ready, Ready};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

// Trait for token validators
pub trait TokenValidator: Clone + Send + Sync + 'static {
    // Validate a token and return user info if valid
    fn validate_token<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<AuthInfo, Error>> + Send + 'a>>;
}

// Auth info returned by validators
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthInfo {
    pub username: String,
    pub groups: Vec<String>,
}

// Generic authentication middleware
#[derive(Clone)]
pub struct Authentication<V> {
    validator: V,
}
impl<V: TokenValidator> Authentication<V> {
    pub fn new(validator: V) -> Self {
        Self { validator }
    }
}

impl<V: TokenValidator> Authentication<Box<V>> {
    pub fn new_boxed(validator: Box<V>) -> Self {
        Self { validator }
    }
}

impl<S, B, V> Transform<S, ServiceRequest> for Authentication<V>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    V: TokenValidator,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthenticationMiddleware<S, V>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationMiddleware {
            service: Rc::new(service),
            validator: self.validator.clone(),
        }))
    }
}

pub struct AuthenticationMiddleware<S, V: TokenValidator> {
    service: Rc<S>,
    validator: V,
}

impl<S, B, V> Service<ServiceRequest> for AuthenticationMiddleware<S, V>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    V: TokenValidator,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let validator = self.validator.clone();
        let srv = self.service.clone();

        Box::pin(async move {
            // Extract bearer token from the request
            let req_head = req.request();
            let bearer_result = BearerAuth::extract(req_head).await;

            match bearer_result {
                Ok(bearer) => {
                    let token = bearer.token();

                    // Validate the token
                    match validator.validate_token(token).await {
                        Ok(auth_info) => {
                            // Add auth info to request extensions
                            req.extensions_mut().insert(auth_info);
                        }
                        Err(e) => {
                            // Token validation failed
                            return Err(e);
                        }
                    }
                }
                Err(_) => {
                    // No bearer token provided
                    return Err(ErrorUnauthorized("Missing or invalid Bearer token"));
                }
            }

            // Continue with request processing
            let res = srv.call(req).await?;
            Ok(res)
        })
    }
}
