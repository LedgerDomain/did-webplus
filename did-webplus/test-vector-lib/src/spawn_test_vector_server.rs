use crate::{TestVectorServerAppState, TestVectorServerConfig};

/// Spawn the test-vector HTTP server with an eagerly generated in-memory catalog.
///
/// Binds `0.0.0.0:{listen_port}`, applies compression / trace / CORS middleware
/// (same stack as the VDR), and returns a join handle for the serve task.
pub async fn spawn_test_vector_server(
    config: TestVectorServerConfig,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    tracing::debug!("{:?}", config);

    let app_state = TestVectorServerAppState::generate(&config)?;

    let middleware_stack = tower::ServiceBuilder::new()
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
        .into_inner();

    let app = axum::Router::new()
        .merge(crate::test_vector_server_routes::get_routes(app_state))
        .layer(middleware_stack)
        .route("/health", axum::routing::get(|| async { "OK" }));

    // 0.0.0.0 so the service is reachable from docker / non-loopback clients.
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.listen_port)).await?;
    tracing::info!(
        "did-webplus test-vector server listening on port {}",
        config.listen_port
    );

    Ok(tokio::task::spawn(async move {
        let _ = axum::serve(listener, app).await;
    }))
}
