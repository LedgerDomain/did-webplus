use crate::VDGConfig;
use std::sync::Arc;

pub async fn spawn_vdg(vdg_config: VDGConfig) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    tracing::info!("{:?}", vdg_config);

    if vdg_config.database_url.starts_with("postgres://") {
        #[cfg(feature = "postgres")]
        {
            use anyhow::Context;

            let pg_pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(vdg_config.database_max_connections)
                .acquire_timeout(std::time::Duration::from_secs(3))
                .connect(&vdg_config.database_url)
                .await
                .context("can't connect to database")?;

            let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(
                did_webplus_doc_storage_postgres::DIDDocStoragePostgres::open_and_run_migrations(
                    pg_pool,
                )
                .await?,
            ));

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
                .merge(crate::services::did_resolve::get_routes(did_doc_store))
                .layer(middleware_stack)
                .route("/health", axum::routing::get(|| async { "OK" }));

            tracing::info!(
                "starting did-webplus-vdg, listening on port {}",
                vdg_config.listen_port
            );

            // This has to be 0.0.0.0 otherwise it won't work in a docker container.
            // 127.0.0.1 is only the loopback device, and isn't available outside the host.
            let listener =
                tokio::net::TcpListener::bind(format!("0.0.0.0:{}", vdg_config.listen_port))
                    .await
                    .unwrap();
            // TODO: Use Serve::with_graceful_shutdown to be able to shutdown the server gracefully, in case aborting
            // the task isn't good enough.
            Ok(tokio::task::spawn(async move {
                // TODO: Figure out if error handling is needed here.
                let _ = axum::serve(listener, app).await;
            }))
        }

        #[cfg(not(feature = "postgres"))]
        {
            panic!("postgres database is only supported by VDR if the `postgres` feature was enabled when building it");
        }
    } else if vdg_config.database_url.starts_with("sqlite://") {
        panic!("VDG should not be run with SQLite DB backend, as SQLite can't handle concurrent writes.  Use Postgres instead.");
        // #[cfg(feature = "sqlite")]
        // {
        //     use anyhow::Context;

        //     let sqlite_pool = sqlx::sqlite::SqlitePoolOptions::new()
        //         .max_connections(vdg_config.database_max_connections)
        //         .acquire_timeout(std::time::Duration::from_secs(3))
        //         .connect(&vdg_config.database_url)
        //         .await
        //         .context("can't connect to database")?;

        //     let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(
        //         did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_and_run_migrations(
        //             sqlite_pool,
        //         )
        //         .await?,
        //     ));

        //     let middleware_stack = tower::ServiceBuilder::new()
        //         .layer(tower_http::compression::CompressionLayer::new())
        //         .layer(
        //             tower_http::trace::TraceLayer::new_for_http()
        //                 .make_span_with(
        //                     tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
        //                 )
        //                 .on_response(
        //                     tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO),
        //                 ),
        //         )
        //         .layer(tower_http::cors::CorsLayer::permissive())
        //         .into_inner();

        //     let app = axum::Router::new()
        //         .merge(crate::services::did_resolve::get_routes(did_doc_store))
        //         .layer(middleware_stack)
        //         .route("/health", axum::routing::get(|| async { "OK" }));

        //     tracing::info!(
        //         "starting did-webplus-vdg, listening on port {}",
        //         vdg_config.listen_port
        //     );

        //     // This has to be 0.0.0.0 otherwise it won't work in a docker container.
        //     // 127.0.0.1 is only the loopback device, and isn't available outside the host.
        //     let listener =
        //         tokio::net::TcpListener::bind(format!("0.0.0.0:{}", vdg_config.listen_port))
        //             .await
        //             .unwrap();
        //     // TODO: Use Serve::with_graceful_shutdown to be able to shutdown the server gracefully, in case aborting
        //     // the task isn't good enough.
        //     Ok(tokio::task::spawn(async move {
        //         // TODO: Figure out if error handling is needed here.
        //         let _ = axum::serve(listener, app).await;
        //     }))
        // }

        // #[cfg(not(feature = "sqlite"))]
        // {
        //     panic!("sqlite database is only supported by VDR if the `sqlite` feature was enabled when building it");
        // }
    } else {
        panic!(
            "unsupported database scheme; database URL was: {:?}",
            vdg_config.database_url
        );
    }
}
