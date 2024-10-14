use crate::{determine_http_scheme, get_did_doc_store, Result};
use std::io::Write;

/// Perform DID resolution for a given query URI, using the "full" resolver, which does all
/// fetching, verification, and storage locally using the specified DID doc store.
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
    // TODO: Figure out how not to print the env var value, since if it ever were a general postgres
    // url, it could contain a password.
    #[arg(
        name = "doc-store",
        env = "DID_WEBPLUS_DOC_STORE",
        short,
        long,
        value_name = "URL",
        default_value = "sqlite://~/.did-webplus/doc-store.db"
    )]
    pub did_doc_store_db_url: String,
    // TODO: Optionally specify a VDG.  You would use this if you wanted to guarantee consortium- or
    // global-scoped agreement on DID docs.
    /// Do not print a newline at the end of the output.
    #[arg(short, long)]
    pub no_newline: bool,
    // TODO: Implement use of a VDG within the full resolver -- it has slightly different logic than
    // talking to a VDR.
}

impl DIDResolveFull {
    pub async fn handle(self) -> Result<()> {
        tracing::debug!("{:?}", self);

        let http_scheme = determine_http_scheme();

        let did_doc_store = get_did_doc_store(&self.did_doc_store_db_url).await?;

        let mut transaction = did_doc_store.begin_transaction(None).await?;
        let did_doc_record = did_webplus_resolver::resolve_did(
            &did_doc_store,
            &mut transaction,
            self.did_query.as_str(),
            http_scheme,
        )
        .await?;
        transaction.commit().await?;

        std::io::stdout().write_all(did_doc_record.did_document_jcs.as_bytes())?;
        if !self.no_newline {
            std::io::stdout().write_all(b"\n")?;
        }

        Ok(())
    }
}
