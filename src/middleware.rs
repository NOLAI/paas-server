use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::dev::{forward_ready, Service, Transform};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::future::{ready, Ready};

pub struct AuthMiddleware;

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
        ok(AuthMiddlewareService { service })
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
            if token == "Bearer mysecrettoken" {
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
