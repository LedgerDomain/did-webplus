use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use std::sync::Arc;

/// Spawn a URD (Universal Resolver Driver).  This is just a DIDResolver running at a specific endpoint on an HTTP server.
pub async fn spawn_urd(
    did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>,
    listen_port: u16,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let urd_app_state = URDAppState { did_resolver_a };
    let router = create_router().with_state(urd_app_state);

    // This has to be 0.0.0.0 otherwise it won't work in a docker container.
    // 127.0.0.1 is only the loopback device, and isn't available outside the host.
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", listen_port)).await?;
    tracing::info!(
        "did:webplus URD (Universal Resolver Driver) listening on port {}",
        listen_port
    );

    // TODO: Use Serve::with_graceful_shutdown to be able to shutdown the server gracefully, in case aborting
    // the task isn't good enough.
    Ok(tokio::task::spawn(async move {
        // TODO: Figure out if error handling is needed here.
        let _ = axum::serve(listener, router).await;
    }))
}

#[derive(Clone)]
struct URDAppState {
    did_resolver_a: Arc<dyn did_webplus_resolver::DIDResolver>,
}

fn create_router() -> Router<URDAppState> {
    Router::new()
        .route("/1.0/identifiers/{query}", get(resolve_did))
        .route("/health", axum::routing::get(|| async { "OK" }))
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(
                    tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
                )
                .on_response(
                    tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO),
                ),
        )
        .layer(tower_http::cors::CorsLayer::permissive())
}

#[tracing::instrument(level = tracing::Level::INFO, ret(level = tracing::Level::DEBUG, Display), err(Debug), skip(urd_app_state))]
async fn resolve_did(
    State(urd_app_state): State<URDAppState>,
    Path(query): Path<String>,
) -> Result<String, (StatusCode, String)> {
    // TODO: Is this log message necessary?
    tracing::info!("Resolving DID query: {}", query);
    let (did_document, _did_document_metadata) = urd_app_state
        .did_resolver_a
        .resolve_did_document_string(
            &query,
            did_webplus_core::RequestedDIDDocumentMetadata::none(),
        )
        .await
        .unwrap();
    Ok(did_document)
}
