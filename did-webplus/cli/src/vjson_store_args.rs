use crate::Result;

#[derive(clap::Args, Debug)]
pub struct VJSONStoreArgs {
    /// Specify the URL to the SQLite VJSON store to use for this operation.  The VJSON store is what
    /// stores validated VJSON blobs.  The URL should have the form `sqlite://<local-path>`.
    // TODO: Figure out how not to print the env var value, since if it ever were a general postgres
    // url, it could contain a password.
    #[arg(
        name = "vjson-store",
        env = "DID_WEBPLUS_VJSON_STORE",
        short,
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/vjson-store.db?mode=rwc"
    )]
    pub vjson_store_db_url: String,
}

impl VJSONStoreArgs {
    pub async fn get_vjson_storage(&self) -> Result<vjson_storage_sqlite::VJSONStorageSQLite> {
        log::debug!(
            "get_vjson_storage; self.vjson_store_db_url: {}",
            self.vjson_store_db_url
        );
        let sqlite_pool = if let Some(vjson_store_db_path_str) =
            self.vjson_store_db_url.strip_prefix("sqlite://")
        {
            // Apply tilde expansion to the path.
            let vjson_store_db_path = expanduser::expanduser(vjson_store_db_path_str)?;
            // See https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
            // TODO: Use std::path::Diplay via Path::display method.
            let vjson_store_db_path_str = vjson_store_db_path.as_os_str().to_str().unwrap();
            log::debug!(
                "Tilde-expanded vjson_store DB path: {}",
                vjson_store_db_path_str
            );
            if !vjson_store_db_path.exists() {
                if let Some(vjson_store_db_url_parent) = vjson_store_db_path.parent() {
                    log::debug!(
                        "Ensuring vjson_store DB parent directory exists: {}",
                        vjson_store_db_url_parent.as_os_str().to_str().unwrap()
                    );
                    // TODO: Probably if the dir exists already this will return an error.
                    std::fs::create_dir_all(vjson_store_db_url_parent)?;
                }
            }
            log::debug!(
                "Connecting to vjson_store DB at {}",
                vjson_store_db_path_str
            );
            sqlx::SqlitePool::connect(vjson_store_db_path_str).await?
        } else {
            unimplemented!("non-SQLite vjson_store DBs are not yet supported.");
        };
        Ok(vjson_storage_sqlite::VJSONStorageSQLite::open_and_run_migrations(sqlite_pool).await?)
    }
    pub async fn get_vjson_store(
        &self,
    ) -> Result<vjson_store::VJSONStore<vjson_storage_sqlite::VJSONStorageSQLite>> {
        let storage = self.get_vjson_storage().await?;
        Ok(vjson_store::VJSONStore::new(storage))
    }
}
