use crate::{DIDResolverArgs, HTTPSchemeArgs, NewlineArgs, Result};
use std::io::Write;

/// Perform DID resolution for a given query URI, using the "full" resolver, which does all
/// fetching, verification, and storage locally using the specified DID doc store.
#[derive(Debug, clap::Parser)]
pub struct DIDResolve {
    /// The DID query URI to be resolved.  Examples:
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=1`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY&versionId=1`.
    /// Note that the & character typically must be within a quoted string in a shell command.
    pub did_query: String,
    #[command(flatten)]
    pub did_resolver_args: DIDResolverArgs,
    #[command(flatten)]
    pub http_scheme_args: HTTPSchemeArgs,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDResolve {
    pub async fn handle(self) -> Result<()> {
        tracing::debug!("{:?}", self);

        let http_scheme = self.http_scheme_args.determine_http_scheme();
        let did_resolver_b = self.did_resolver_args.get_did_resolver(http_scheme).await?;
        // TODO: Handle metadata
        let (did_document_string, _did_doc_metadata) = did_resolver_b
            .resolve_did_document_string(
                self.did_query.as_str(),
                did_webplus_core::RequestedDIDDocumentMetadata::none(),
            )
            .await?;

        std::io::stdout().write_all(did_document_string.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
