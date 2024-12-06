use crate::{DIDDocStoreArgs, HTTPSchemeArgs, NewlineArgs, Result};
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
    #[command(flatten)]
    pub did_doc_store_args: DIDDocStoreArgs,
    #[command(flatten)]
    pub http_scheme_args: HTTPSchemeArgs,
    // TODO: Optionally specify a VDG.  You would use this if you wanted to guarantee consortium- or
    // global-scoped agreement on DID docs.
    #[command(flatten)]
    pub newline_args: NewlineArgs,
    // TODO: Implement use of a VDG within the full resolver -- it has slightly different logic than
    // talking to a VDR.
}

impl DIDResolveFull {
    pub async fn handle(self) -> Result<()> {
        tracing::debug!("{:?}", self);

        let did_resolver = did_webplus_resolver::DIDResolverFull {
            did_doc_store: self.did_doc_store_args.get_did_doc_store().await?,
            http_scheme: self.http_scheme_args.determine_http_scheme(),
        };
        use did_webplus_resolver::DIDResolver;
        // TODO: Handle metadata
        let (did_document_string, _did_doc_metadata) = did_resolver
            .resolve_did_document_string(
                self.did_query.as_str(),
                did_webplus::RequestedDIDDocumentMetadata::none(),
            )
            .await?;

        std::io::stdout().write_all(did_document_string.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
