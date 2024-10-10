use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::{from_fn, Logger, Next};
use actix_web::{web, App, Error, HttpRequest, HttpServer};
use dotenv::dotenv;
use env_logger::Env;
use log::{error, info};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use unkey::models::VerifyKeyRequest;
use unkey::Client as UnkeyClient;

#[derive(Serialize)]
struct RateLimitRequest {
    namespace: String,
    identifier: String,
    limit: u32,
    duration: u64,
    cost: u32,
    #[serde(rename = "async")]
    async_field: bool,
    meta: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    resources: Vec<Resource>, // Default to an empty array if no resources are provided
}

#[derive(Serialize)]
struct Resource {
    r#type: String,
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    error: ApiError,
}

#[derive(Deserialize)]
struct ApiError {
    code: String,
    docs: String,
    message: String,
    #[serde(rename = "requestId")]
    request_id: String,
}

#[derive(Deserialize)]
struct RateLimitResponse {
    limit: Option<i32>,
    remaining: Option<i32>,
    reset: Option<u64>,
    success: Option<bool>,
}

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

async fn verify_key(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    info!("Middleware start");

    let headers = req.headers().clone(); // Clone the headers so req is not borrowed later

    info!("Headers: {:?}", headers);

    let data = req.app_data::<web::Data<AppState>>().unwrap();
    let client = req.app_data::<web::Data<Client>>().unwrap();

    let connection_info = req.connection_info().clone();
    let user_ip = connection_info.realip_remote_addr().unwrap_or("unknown").to_string();

    let authorization_header = if let Some(header_value) = headers.get("Authorization") {
        match header_value.to_str() {
            Ok(value) if value.starts_with("Bearer ") => value.trim_start_matches("Bearer ").to_string(),
            _ => {
                return Err(actix_web::error::ErrorUnauthorized(
                    "Invalid Authorization header format",
                ))
            }
        }
    } else {
        return Err(actix_web::error::ErrorUnauthorized("Authorization header missing"));
    };

    let verify_request = VerifyKeyRequest {
        key: authorization_header.to_string(),
        api_id: data.unkey_api_id.clone().into(),
    };

    match data.unkey_client.verify_key(verify_request).await {
        Ok(res) if res.valid => {
            let rate_limit_request = RateLimitRequest {
                namespace: "test_protected".to_string(), // Namespace for the rate limit
                identifier: user_ip,                     // Identifier for the rate limit
                limit: 10,
                duration: 60000,
                cost: 2,
                async_field: true,
                meta: HashMap::new(),
                resources: vec![],
            };

            let unkey_root_key = env::var("UNKEY_ROOT_KEY").expect("UNKEY_ROOT_KEY must be set");

            let rate_limit_response = client
                .post("https://api.unkey.dev/v1/ratelimits.limit")
                .bearer_auth(unkey_root_key)
                .header("Content-Type", "application/json")
                .json(&rate_limit_request)
                .send()
                .await
                .unwrap();

            if rate_limit_response.status().is_success() {
                let rate_limit_result = match rate_limit_response.json::<RateLimitResponse>().await {
                    Ok(response) => response,
                    Err(err) => {
                        log::error!("Failed to deserialize rate limit response: {:?}", err);
                        return Err(actix_web::error::ErrorInternalServerError(
                            "Failed to parse rate limit response",
                        ));
                    }
                };

                if let Some(remaining) = rate_limit_result.remaining {
                    if remaining > 0 {
                        // Rate limit passed, proceed to the next middleware or handler
                        let res = next.call(req).await?;
                        Ok(res)
                    } else {
                        log::info!("Rate limit exceeded. Resets at: {:?}", rate_limit_result.reset);
                        return Err(actix_web::error::ErrorTooManyRequests("Rate limit exceeded"));
                    }
                } else {
                    log::error!("Rate limit response missing 'remaining' field");
                    return Err(actix_web::error::ErrorInternalServerError(
                        "Invalid rate limit response",
                    ));
                }
            } else {
                // Parse the error response
                let error_response: ApiErrorResponse = rate_limit_response.json().await.map_err(|err| {
                    log::error!("Failed to parse error response: {:?}", err);
                    actix_web::error::ErrorInternalServerError("Failed to parse error response")
                })?;

                // Log the error and return a meaningful error message to the user
                log::error!(
                    "Rate limit request failed. Code: {}, Message: {}, Docs: {}, Request ID: {}",
                    error_response.error.code,
                    error_response.error.message,
                    error_response.error.docs,
                    error_response.error.request_id
                );

                return Err(actix_web::error::ErrorBadRequest(format!(
                    "Rate limit request failed: {} (Request ID: {})",
                    error_response.error.message, error_response.error.request_id
                )));
            }
        }
        Ok(res) => {
            error!("Key verification failed: {:?}", res);
            Err(actix_web::error::ErrorUnauthorized("Key verification failed"))
        }
        Err(err) => {
            error!("Key verification failed: {:?}", err);
            Err(actix_web::error::ErrorUnauthorized("Key verification failed"))
        }
    }
}

async fn public(_req: HttpRequest) -> String {
    "Hello, world!".to_owned()
}

async fn protected(_req: HttpRequest) -> String {
    "Hello, protected world!".to_owned()
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
    let client = web::Data::new(Client::new());

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .app_data(client.clone())
            .app_data(shared_data.clone())
            .service(
                web::scope("/api/v1")
                    .route("/public", web::get().to(public))
                    .route("/protected", web::get().wrap(from_fn(verify_key)).to(protected)),
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
