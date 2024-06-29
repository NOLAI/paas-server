use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::dev::{forward_ready, Service, Transform};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::future::{ready, Ready};
use std::fs;
use std::sync::Arc;

pub struct AuthMiddleware {
    token: Arc<String>,
    token: Arc<String>,
}

impl AuthMiddleware {
    pub fn new(token_file: &str) -> Self {
        let token = fs::read_to_string(token_file)
            .expect("Failed to read token file")
            .trim()
            .to_string();
        AuthMiddleware {
            token: Arc::new(token),
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
            token: Arc::clone(&self.token),
        })
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
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
            if token == format!("Bearer {}", self.token) {
                let fut = self.service.call(req);
                return Box::pin(async move {
                    let res = fut.await?;
                    Ok(res)
                });
            }
        }

        Box::pin(async { Ok(req.into_response(HttpResponse::Unauthorized().finish().into_body())) })
    }
}
