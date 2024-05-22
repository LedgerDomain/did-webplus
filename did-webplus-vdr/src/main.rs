mod config;
mod models;
mod services;

use std::env;
use std::net::SocketAddr;

use anyhow::Context;
use axum::{http::StatusCode, routing, Router};
use config::AppConfig;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 1 {
        tracing::info!("Reading config from file: {:?}", args[1]);
        Some(&args[1])
    } else {
        tracing::info!("No config file found");
        None
    };

    let config = AppConfig::new(config_path).context("Failed to load configuration")?;

    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    // TODO: Make env var to control full/compact/pretty/json formatting of logs
    let tracing_subscriber_fmt = tracing_subscriber::fmt()
        .with_target(true)
        .with_line_number(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());
    match config.log_format {
        config::LogFormat::Compact => tracing_subscriber_fmt.compact().init(),
        config::LogFormat::Pretty => tracing_subscriber_fmt.pretty().init(),
    }

    tracing::info!("Config: {:?}", config);

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&config.database_url)
        .await
        .context("can't connect to database")?;

    sqlx::migrate!().run(&pool).await?;

    let middleware_stack = ServiceBuilder::new()
        .layer(CompressionLayer::new())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(CorsLayer::permissive())
        .into_inner();

    let app = Router::new()
        .merge(services::did::get_routes(&pool, &config))
        .layer(middleware_stack)
        .route("/health", routing::get(|| async { "OK" }));

    tracing::info!(
        "starting did-webplus-vdr, listening on port {}",
        config.port
    );

    // This has to be 0.0.0.0 otherwise it won't work in a docker container.
    // 127.0.0.1 is only the loopback device, and isn't available outside the host.
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}

fn parse_did_document(
    did_document_body: &str,
) -> Result<did_webplus::DIDDocument, (StatusCode, String)> {
    serde_json::from_str(did_document_body).map_err(|_| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "malformed DID document".to_string(),
        )
    })
}
