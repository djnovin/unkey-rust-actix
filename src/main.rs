use actix_web::{middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer};
use dotenv::dotenv;
use env_logger::Env;
use log::{error, info, warn};
use std::env;
use unkey::models::VerifyKeyRequest;
use unkey::Client as UnkeyClient;

#[derive(Clone)]
struct UnkeyApiId(String);

impl From<UnkeyApiId> for String {
    fn from(api_id: UnkeyApiId) -> Self {
        api_id.0
    }
}

struct AppState {
    unkey_client: UnkeyClient,
    unkey_api_id: UnkeyApiId,
}

async fn public(_req: HttpRequest) -> String {
    "Hello, world!".to_owned()
}

async fn protected(req: HttpRequest, data: web::Data<AppState>) -> HttpResponse {
    let auth_header = match req.headers().get("Authorization") {
        Some(header) => header,
        None => {
            warn!("Missing Authorization header");
            return HttpResponse::Unauthorized().body("Missing Authorization header");
        }
    };

    let auth_str = match auth_header.to_str() {
        Ok(auth_str) => auth_str,
        Err(_) => {
            warn!("Invalid Authorization header format");
            return HttpResponse::Unauthorized().body("Invalid Authorization header format");
        }
    };

    let token = auth_str.trim_start_matches("Bearer ");
    info!("Received token: {}", token);

    let verify_request = VerifyKeyRequest {
        key: token.to_string(),
        api_id: data.unkey_api_id.clone().into(),
    };

    match data.unkey_client.verify_key(verify_request).await {
        Ok(res) if res.valid => {
            info!("Token verified successfully");
            HttpResponse::Ok().body("Protected data")
        }
        Ok(_) => {
            warn!("Token verification failed");
            HttpResponse::Unauthorized().body("Invalid token")
        }
        Err(err) => {
            error!("Error verifying token: {:?}", err);
            HttpResponse::InternalServerError().body(format!("Error: {:?}", err))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("PORT must be a number");

    let unkey_root_key = env::var("UNKEY_ROOT_KEY").expect("UNKEY_ROOT_KEY must be set");
    let unkey_api_id = UnkeyApiId(env::var("UNKEY_API_ID").expect("UNKEY_API_ID must be set"));

    let unkey_client = UnkeyClient::new(&unkey_root_key);

    let app_state = AppState {
        unkey_client,
        unkey_api_id,
    };

    let shared_data = web::Data::new(app_state);

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .app_data(shared_data.clone())
            .service(
                web::scope("/api/v1")
                    .route("/public", web::get().to(public))
                    .route("/protected", web::get().to(protected)),
            )
    })
    .bind(("127.0.0.1", port))?
    .shutdown_timeout(60)
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_public_route() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(AppState {
                    unkey_client: UnkeyClient::new(""),
                    unkey_api_id: UnkeyApiId("".to_string()),
                }))
                .service(web::scope("/api/v1").route("/public", web::get().to(public))),
        )
        .await;

        let req = test::TestRequest::get().uri("/api/v1/public").to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = test::read_body(resp).await;
        assert_eq!(body, "Hello, world!");
    }
}
