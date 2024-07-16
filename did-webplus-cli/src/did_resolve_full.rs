use crate::{determine_http_scheme, Result};
use did_webplus_doc_storage_sqlite::DIDDocStorageSQLite;
use did_webplus_doc_store::DIDDocStore;
use sqlx::migrate::MigrateDatabase;

/// Perform DID resolution for a given query URI, using the "thin" resolver, relying on a VDG.
#[derive(Debug, clap::Parser)]
pub struct DIDResolveFull {
    /// The DID query URI to be resolved.  Examples:
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=1`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY&versionId=1`.
    /// Note that the & character typically must be within a quoted string in a shell command.
    pub did_query: String,
    /// Specify the URL to the SQLite DID doc store to use for the "full" resolver.  This is
    /// what stores validated DID docs.  It should have the form `sqlite://<local-path>`.
    // TODO: Default in some home directory?
    // TODO: Figure out how not to print the env var value, since if it ever were a general postgres
    // url, it could contain a password.
    #[arg(
        name = "doc-store",
        env = "DID_WEBPLUS_CLI_DOC_STORE",
        short,
        long,
        value_name = "URL"
    )]
    pub did_doc_store_url: String,
    // TODO: Implement use of a VDG within the full resolver -- it has slightly different logic than
    // talking to a VDR.
}

impl DIDResolveFull {
    pub async fn handle(self) -> Result<()> {
        tracing::debug!("{:?}", self);

        let http_scheme = determine_http_scheme();

        // TODO: Handle home dir stuff
        // Ensure the DB exists before attempting to open.
        if !sqlx::Sqlite::database_exists(&self.did_doc_store_url).await? {
            sqlx::Sqlite::create_database(&self.did_doc_store_url).await?;
        }
        let sqlite_pool = sqlx::SqlitePool::connect(self.did_doc_store_url.as_str()).await?;
        let did_doc_storage = DIDDocStorageSQLite::open_and_run_migrations(sqlite_pool).await?;
        let did_doc_store = DIDDocStore::new(did_doc_storage);

        let mut transaction = did_doc_store.begin_transaction(None).await?;
        let did_doc_record = did_webplus_resolver::resolve_did(
            &did_doc_store,
            &mut transaction,
            self.did_query.as_str(),
            http_scheme,
        )
        .await?;
        transaction.commit().await?;

        println!("{}", did_doc_record.did_document_jcs);
        Ok(())
    }
}
