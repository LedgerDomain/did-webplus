use crate::{determine_http_scheme, NewlineArgs, Result};
use std::io::Write;

/// Perform DID resolution for a given query URI, using the "raw" resolution method, which only does
/// a limited subset of verification, so should not be used for any production purposes.  THIS IS
/// INTENDED ONLY FOR DEVELOPMENT AND TESTING PURPOSES.
#[derive(Debug, clap::Parser)]
pub struct DIDResolveRaw {
    /// The DID query URI to be resolved.  Examples:
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=1`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY&versionId=1`.
    /// Note that the & character typically must be within a quoted string in a shell command.
    pub did_query: String,
    // /// Specify the scheme to use for the VDR in the DID resolution request.  Must either be "http" or "https".
    // // TODO: Validation in clap derive for this constraint.
    // #[arg(short, long, value_name = "SCHEME", default_value = "https")]
    // pub vdr_scheme: String,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDResolveRaw {
    pub async fn handle(self) -> Result<()> {
        tracing::debug!("{:?}", self);

        let did_resolver = did_webplus_resolver::DIDResolverRaw {
            http_scheme: determine_http_scheme(),
        };
        use did_webplus_resolver::DIDResolver;
        let (did_document_string, _did_doc_metadata) = did_resolver
            .resolve_did_document_string(
                self.did_query.as_str(),
                did_webplus::RequestedDIDDocumentMetadata::none(),
            )
            .await?;
        // TODO: handle metadata

        std::io::stdout().write_all(did_document_string.as_bytes())?;
        self.newline_args
            .print_newline_if_necessary(&mut std::io::stdout())?;

        Ok(())
    }
}
