use std::cell::RefCell;
use std::rc::Rc;
use actix_web::{web, Error, FromRequest, HttpMessage};
use actix_web::error::{ErrorForbidden, ErrorUnauthorized};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::collections::HashMap;
use std::sync::Arc;
use serde::Deserialize;
use std::fs;
use actix_web::body::MessageBody;
use actix_web::web::{BytesMut, Json};
use futures_util::{StreamExt, TryFutureExt};
use crate::application::PseudonymizationRequest;
use crate::middleware::AuthenticationInfo;

#[derive(Deserialize)]
struct DomainConfig {
    from: HashMap<String, Vec<String>>,
    to: HashMap<String, Vec<String>>,
}

#[derive(Clone)]
pub struct DomainMiddleware {
    from: Arc<HashMap<String, Vec<String>>>,
    to: Arc<HashMap<String, Vec<String>>>,
}

impl DomainMiddleware {
    pub fn new(domain_file: &str) -> Self {
        let file_content = fs::read_to_string(domain_file)
            .expect("Failed to read domain file");

        // TODO: Implement the DOMAIN Config struct
        let token_config: DomainConfig = serde_yml::from_str(&file_content)
            .expect("Failed to parse token file");

        DomainMiddleware {
            from: Arc::new(token_config.from),
            to: Arc::new(token_config.to),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for DomainMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = DomainMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(DomainMiddlewareService {
            service,
            from: Arc::clone(&self.from),
            to: Arc::clone(&self.to),
        })
    }
}

pub struct DomainMiddlewareService<S> {
    service: S,
    from: Arc<HashMap<String, Vec<String>>>,
    to: Arc<HashMap<String, Vec<String>>>,
}

impl<S, B> Service<ServiceRequest> for DomainMiddlewareService<S>
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
        let auth_info = req.extensions().get::<AuthenticationInfo>().cloned(); // Get user authentication info
        let from_map = Arc::clone(&self.from);
        let to_map = Arc::clone(&self.to);
        
        
        if let Some(auth_info) = auth_info {
            let username = auth_info.username.as_str(); // Get the username from the auth info
            
            let user_from_contexts = from_map.get(username);
            let user_to_contexts = to_map.get(username);
            
            println!("Username: {}", username);
            println!("User from contexts: {:?}", user_from_contexts);
            println!("User to contexts: {:?}", user_to_contexts);
            
                let fut = self.service.call(req);
                return Box::pin(async move {
                    let res = fut.await?;
                    Ok(res)
                });

            // Box::pin(async move {
            //     // let payload = req.take_payload();
            //     // let mut request_body = BytesMut::new();
            //     // while let Some(chunk) = req.take_payload().next().await {
            //     //     request_body.extend_from_slice(&chunk?);
            //     // }
            //     // let request_data: PseudonymizationRequest = serde_json::from_slice(&request_body).unwrap();
            //     // 
            //     
            //     // let (http_req, payload) = req.into_parts();
            //     // Extract the request body (PseudonymizationRequest) from the request
            //     // let request_data = match web::Json::<PseudonymizationRequest>::from_request(&http_req, payload).await {
            //     //     Ok(req_data) => req_data.into_inner(), // Successfully parsed request
            //     //     Err(_) => return Err(ErrorForbidden("Invalid request format")),
            //     // };
            // 
            //     // Retrieve the user's allowed 'from' and 'to' contexts from the maps
            //     let user_from_contexts = from_map.get(username);
            //     let user_to_contexts = to_map.get(username);
            // 
            //     // Check if the user has access to the 'enc_context' and 'dec_context'
            //     if let (Some(from), Some(to)) = (user_from_contexts, user_to_contexts) {
            //         if from.contains(&request_data.enc_context) && to.contains(&request_data.dec_context) {
            //             let fut = svc.call(req);
            // 
            //             // If user has access, forward the request
            //             let res = fut.await?;
            //             return Ok(res);
            //         }
            //     }
            // 
            //     // If access is denied, return forbidden
            //     Err(ErrorForbidden("User does not have access to the requested contexts"))
            // })
        }
    else{
        Box::pin(async move { Err(ErrorUnauthorized("No authentication info provided")) })
    }
        }
}
