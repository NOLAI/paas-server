mod auth_middleware;
mod application;
mod domain_middleware;

use actix_web::{web, App, HttpServer};
use actix_web::middleware::{Logger};
use env_logger::Env;

use crate::application::*;
use crate::auth_middleware::AuthMiddleware;
use crate::domain_middleware::DomainMiddleware;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth_middleware = AuthMiddleware::new("resources/tokens.yml");
    let domain_middleware = DomainMiddleware::new("resources/allowlist.yml");
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(auth_middleware.clone()) // Not needed for random
            .route("/", web::get().to(index))
            .route("/random", web::get().to(random))
            .service(
                web::scope("/pseudonymize")
                    .route("", web::post().to(pseudonymize)
                        .wrap(domain_middleware.clone())
                    ))
        //    .route("/rekey", web::post().to(pseudonymize)) // TODO
        // TODO: Start session en dan krijg je een session terug. Je kan meerdere sessies draaien, alleen na 24H worden ze verwijderd.
    })
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
