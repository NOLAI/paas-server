mod middleware;
mod application;

use actix_web::{web, App, HttpServer};
use actix_web::middleware::Logger;
use env_logger::Env;

use crate::application::*;
use crate::middleware::AuthMiddleware;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth_middleware = AuthMiddleware::new("tokens.yml");

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(auth_middleware.clone())
            .route("/", web::get().to(index))
            .route("/random", web::get().to(random))
            .route("/pseudonymize", web::post().to(pseudonymize))
            // .route("/rekey", web::post().to(pseudonymize))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
