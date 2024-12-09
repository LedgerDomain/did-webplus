use crate::Result;

#[derive(clap::Args, Debug)]
pub struct DIDDocStoreArgs {
    /// Specify the URL to the SQLite DID doc store to use for this operation.  The doc store is what
    /// stores validated DID docs.  The URL should have the form `sqlite://<local-path>`.
    // TODO: Figure out how not to print the env var value, since if it ever were a general postgres
    // url, it could contain a password.
    #[arg(
        name = "did-doc-store",
        env = "DID_WEBPLUS_DID_DOC_STORE",
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/did-doc-store.db?mode=rwc"
    )]
    pub did_doc_store_db_url: String,
}

impl DIDDocStoreArgs {
    pub async fn get_did_doc_storage(
        &self,
    ) -> Result<did_webplus_doc_storage_sqlite::DIDDocStorageSQLite> {
        log::debug!(
            "get_did_doc_storage; self.did_doc_store_db_url: {}",
            self.did_doc_store_db_url
        );
        let sqlite_pool = if let Some(did_doc_db_path_str) =
            self.did_doc_store_db_url.strip_prefix("sqlite://")
        {
            // Apply tilde expansion to the path.
            let did_doc_store_db_path = expanduser::expanduser(did_doc_db_path_str)?;
            // See https://stackoverflow.com/questions/37388107/how-to-convert-the-pathbuf-to-string
            // TODO: Use std::path::Diplay via Path::display method.
            let did_doc_store_db_path_str = did_doc_store_db_path.as_os_str().to_str().unwrap();
            log::debug!(
                "Tilde-expanded did_doc_store DB path: {}",
                did_doc_store_db_path_str
            );
            if !did_doc_store_db_path.exists() {
                if let Some(did_doc_db_url_parent) = did_doc_store_db_path.parent() {
                    log::debug!(
                        "Ensuring did_doc_store DB parent directory exists: {}",
                        did_doc_db_url_parent.as_os_str().to_str().unwrap()
                    );
                    // TODO: Probably if the dir exists already this will return an error.
                    std::fs::create_dir_all(did_doc_db_url_parent)?;
                }
            }
            log::debug!(
                "Connecting to did_doc_store DB at {}",
                did_doc_store_db_path_str
            );
            sqlx::SqlitePool::connect(did_doc_store_db_path_str).await?
        } else {
            unimplemented!("non-SQLite did_doc_store DBs are not yet supported.");
        };
        Ok(
            did_webplus_doc_storage_sqlite::DIDDocStorageSQLite::open_and_run_migrations(
                sqlite_pool,
            )
            .await?,
        )
    }
    pub async fn get_did_doc_store(
        &self,
    ) -> Result<
        did_webplus_doc_store::DIDDocStore<did_webplus_doc_storage_sqlite::DIDDocStorageSQLite>,
    > {
        let storage = self.get_did_doc_storage().await?;
        Ok(did_webplus_doc_store::DIDDocStore::new(storage))
    }
}
