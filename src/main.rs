mod middleware;
mod application;
mod domain_middleware;

use actix_web::{web, App, HttpServer};
use actix_web::middleware::Logger;
use env_logger::Env;

use crate::application::*;
use crate::middleware::AuthMiddleware;
use crate::domain_middleware::DomainMiddleware;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth_middleware = AuthMiddleware::new("tokens.yml");
    let domain_middleware = DomainMiddleware::new("whitelist.yml");

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(auth_middleware.clone()) // Are executed in the reverse order of wrapping
            .route("/", web::get().to(index))
            .route("/random", web::get().to(random))
            .service(
                web::scope("/pseudonymize")
                    .route("", web::post().to(pseudonymize)
                        .wrap(domain_middleware.clone()),
                    ))
        // .route("/pseudonymize", web::post().to(pseudonymize))
        // .route("/rekey", web::post().to(pseudonymize))
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
