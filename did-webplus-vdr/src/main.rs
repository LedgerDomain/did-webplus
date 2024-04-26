mod models;
mod services;

use std::net::SocketAddr;

use anyhow::Context;
use axum::{routing, Router};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Ignore errors, since there may not be a .env file (e.g. in docker image)
    let _ = dotenvy::dotenv();

    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    // TODO: Make env var to control full/compact/pretty/json formatting of logs
    tracing_subscriber::fmt()
        .with_target(false)
        .pretty()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let _ = dotenvy::var("SERVICE_DOMAIN").expect("SERVICE_DOMAIN must be set");

    let database_url = dotenvy::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let max_connections: u32 = dotenvy::var("DATABASE_MAX_CONNECTIONS")
        .unwrap_or("10".to_string())
        .parse()?;
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&database_url)
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
        .merge(services::microledger::get_routes(&pool))
        .layer(middleware_stack)
        .route("/health", routing::get(|| async { "OK" }));

    tracing::error!("testing error level log");
    tracing::warn!("testing warn level log");
    tracing::info!("testing info level log");
    tracing::debug!("testing debug level log");
    tracing::trace!("testing trace level log");

    let port: u16 = dotenvy::var("PORT").unwrap_or("80".to_string()).parse()?;
    tracing::info!("starting did-webplus-vdr, listening on port {}", port);

    // This has to be 0.0.0.0 otherwise it won't work in a docker container.
    // 127.0.0.1 is only the loopback device, and isn't available outside the host.
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}
