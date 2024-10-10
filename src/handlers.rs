use actix_web::HttpRequest;

pub async fn public(_req: HttpRequest) -> String {
    "Hello, world!".to_owned()
}

pub async fn protected(_req: HttpRequest) -> String {
    "Hello, protected world!".to_owned()
}
