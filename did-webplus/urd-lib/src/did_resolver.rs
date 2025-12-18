use crate::Result;
use std::sync::Arc;

pub async fn create_did_resolver_full(
    database_url: &str,
    vdg_host_o: Option<&str>,
    http_options_o: Option<did_webplus_core::HTTPOptions>,
) -> Result<did_webplus_resolver::DIDResolverFull> {
    let did_doc_store = if database_url.starts_with("postgres://") {
        #[cfg(feature = "postgres")]
        {
            let postgres_pool = sqlx::PgPool::connect(database_url).await?;
            let did_doc_storage =
                did_webplus_doc_storage_postgres::DIDDocStoragePostgres::open_and_run_migrations(
                    postgres_pool,
                )
                .await?;
            did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage))
        }
        #[cfg(not(feature = "postgres"))]
        {
            anyhow::bail!(
                "Postgres support is not enabled -- must build with the `postgres` feature enabled"
            );
        }
    } else if database_url.starts_with("sqlite://") {
        let sqlite_pool = sqlx::SqlitePool::connect(database_url).await?;
        let did_doc_storage =
            did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_and_run_migrations(
                sqlite_pool,
            )
            .await?;
        did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage))
    } else {
        anyhow::bail!(
            "Unsupported database URL {:?} -- must start with `postgres://` or `sqlite://`",
            database_url
        );
    };
    let did_resolver_full = did_webplus_resolver::DIDResolverFull::new(
        did_doc_store,
        vdg_host_o.as_deref(),
        http_options_o,
    )?;
    Ok(did_resolver_full)
}
