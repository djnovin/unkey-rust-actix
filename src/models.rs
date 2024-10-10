use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use unkey::Client as UnkeyClient;

#[derive(Clone)]
pub struct UnkeyApiId(pub String);

pub struct AppState {
    pub unkey_client: UnkeyClient,
    pub unkey_api_id: UnkeyApiId,
}

#[derive(Serialize)]
pub struct RateLimitRequest {
    pub namespace: String,
    pub identifier: String,
    pub limit: u32,
    pub duration: u64,
    pub cost: u32,
    #[serde(rename = "async")]
    pub async_field: bool,
    pub meta: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<Resource>, // Default to an empty array if no resources are provided
}

#[derive(Serialize)]
pub struct Resource {
    pub r#type: String,
    pub id: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct ApiErrorResponse {
    pub error: ApiError,
}

#[derive(Deserialize)]
pub struct ApiError {
    pub code: String,
    pub docs: String,
    pub message: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

#[derive(Deserialize)]
pub struct RateLimitResponse {
    #[allow(dead_code)]
    pub limit: Option<i32>,
    pub remaining: Option<i32>,
    pub reset: Option<u64>,
    #[allow(dead_code)]
    pub success: Option<bool>,
}
