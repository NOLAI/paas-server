use actix_web::{web, App, HttpResponse, HttpServer, Responder, middleware};
use serde::{Deserialize, Serialize};
mod middleware;

#[derive(Serialize, Deserialize)]
struct MyObj {
    name: String,
}

async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

async fn get_item() -> impl Responder {
    let obj = MyObj {
        name: "item1".to_string(),
    };
    HttpResponse::Ok().json(obj)
}

async fn create_item(item: web::Json<MyObj>) -> impl Responder {
    HttpResponse::Created().json(item.into_inner())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth_middleware = middleware::AuthMiddleware::new("token.txt");

    HttpServer::new(move || {
        App::new()
            .wrap(auth_middleware.clone())
            .route("/", web::get().to(index))
            .route("/item", web::get().to(get_item))
            .route("/item", web::post().to(create_item))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
