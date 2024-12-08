use crate::VDGConfig;
use anyhow::Context;
use axum::{routing, Router};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

pub async fn spawn_vdg(vdg_config: VDGConfig) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    tracing::info!("{:?}", vdg_config);

    let pg_pool = PgPoolOptions::new()
        .max_connections(vdg_config.database_max_connections)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&vdg_config.database_url)
        .await
        .context("can't connect to database")?;

    let did_doc_store = did_webplus_doc_store::DIDDocStore::new(
        did_webplus_doc_storage_postgres::DIDDocStoragePostgres::open_and_run_migrations(pg_pool)
            .await?,
    );

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
        .merge(crate::services::did_resolve::get_routes(did_doc_store))
        .layer(middleware_stack)
        .route("/health", routing::get(|| async { "OK" }));

    tracing::info!(
        "starting did-webplus-vdg, listening on port {}",
        vdg_config.port
    );

    // This has to be 0.0.0.0 otherwise it won't work in a docker container.
    // 127.0.0.1 is only the loopback device, and isn't available outside the host.
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", vdg_config.port))
        .await
        .unwrap();
    // TODO: Use Serve::with_graceful_shutdown to be able to shutdown the server gracefully, in case aborting
    // the task isn't good enough.
    Ok(tokio::task::spawn(async move {
        // TODO: Figure out if error handling is needed here.
        let _ = axum::serve(listener, app).await;
    }))
}
