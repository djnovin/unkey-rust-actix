use actix_web::body::MessageBody;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::middleware::Next;
use actix_web::{web, Error};
use log::{error, info};
use reqwest::Client;
use std::collections::HashMap;
use std::env;
use unkey::models::VerifyKeyRequest;

use crate::models::{ApiErrorResponse, AppState, RateLimitRequest, RateLimitResponse};

pub async fn verify_key(
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
