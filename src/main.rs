use ::unkey::Client as UnkeyClient;
use actix_web::{middleware::Logger, web, App, HttpRequest, HttpServer};
use dotenv::dotenv;
use env_logger::Env;
use std::env;

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

async fn protected(_req: HttpRequest) -> String {
    "Hello, world!".to_owned()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("PORT must be a number");

    let unkey_root_key = env::var("UNKEY_ROOT_KEY").unwrap_or_default();
    let unkey_api_id = UnkeyApiId(env::var("UNKEY_API_ID").unwrap_or_default());

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
    .run()
    .await
}
