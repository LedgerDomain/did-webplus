use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
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
        .route("/health", get(health_check))
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

#[tracing::instrument(level = tracing::Level::DEBUG, err(Debug), skip(urd_app_state))]
async fn resolve_did(
    State(urd_app_state): State<URDAppState>,
    Path(query): Path<String>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    tracing::debug!("Resolving DID query: {}", query);
    let (did_document, _did_document_metadata, _did_resolution_metadata) = urd_app_state
        .did_resolver_a
        .resolve_did_document_string(
            &query,
            did_webplus_core::DIDResolutionOptions::no_metadata(false),
        )
        .await
        .map_err(|e| match e {
            did_webplus_resolver::Error::DIDDocStoreError(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            }
            did_webplus_resolver::Error::DIDResolutionFailure(http_error) => {
                (http_error.status_code, http_error.description.into_owned())
            }
            did_webplus_resolver::Error::DIDResolutionFailure2(did_resolution_metadata) => (
                StatusCode::NOT_FOUND,
                serde_json::to_string(&did_resolution_metadata).unwrap(),
            ),
            did_webplus_resolver::Error::FailedConstraint(description) => {
                (StatusCode::UNPROCESSABLE_ENTITY, description.into_owned())
            }
            did_webplus_resolver::Error::GenericError(description) => {
                (StatusCode::INTERNAL_SERVER_ERROR, description.into_owned())
            }
            did_webplus_resolver::Error::InvalidVerifier(description) => {
                (StatusCode::BAD_REQUEST, description.into_owned())
            }
            did_webplus_resolver::Error::MalformedDIDDocument(description) => {
                (StatusCode::UNPROCESSABLE_ENTITY, description.into_owned())
            }
            did_webplus_resolver::Error::MalformedDIDQuery(description) => {
                (StatusCode::BAD_REQUEST, description.into_owned())
            }
            did_webplus_resolver::Error::MalformedVDGHost(description) => {
                (StatusCode::BAD_REQUEST, description.into_owned())
            }
            did_webplus_resolver::Error::StorageError(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            }
        })?;
    tracing::trace!("resolved DID document: {}", did_document);
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "application/did+json".parse().unwrap());
    Ok((headers, did_document))
}

#[tracing::instrument(level = tracing::Level::TRACE, ret(level = tracing::Level::TRACE, Display), err(Debug), skip(_urd_app_state))]
async fn health_check(
    State(_urd_app_state): State<URDAppState>,
) -> Result<String, (StatusCode, String)> {
    Ok("OK".to_string())
}
