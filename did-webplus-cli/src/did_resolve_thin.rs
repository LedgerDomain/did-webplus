use crate::{determine_http_scheme, parse_url, NewlineArgs, Result};
use std::io::Write;

/// Perform DID resolution for a given query URI, using the "thin" resolver, relying on a VDG
/// (Verifiable Data Gateway) to perform fetching, validation, and storage.  This is useful
/// for clients that can't or do not want to implement the full DID resolution logic themselves.
#[derive(Debug, clap::Parser)]
pub struct DIDResolveThin {
    /// The DID query URI to be resolved.  Examples:
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=1`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY&versionId=1`.
    /// Note that the & character typically must be within a quoted string in a shell command.
    pub did_query: String,
    /// Specify the URL of the "resolve" endpoint of the VDG to use for DID resolution.  The URL can
    /// omit the scheme (i.e. the "https://" portion).  The URL must not contain a query string
    /// or fragment.
    #[arg(
        name = "vdg",
        env = "DID_WEBPLUS_VDG",
        short,
        long,
        value_name = "URL",
        value_parser = parse_url,
    )]
    pub vdg_resolve_endpoint: url::Url,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDResolveThin {
    pub async fn handle(mut self) -> Result<()> {
        tracing::debug!("{:?}", self);

        let http_scheme = determine_http_scheme();

        // Override HTTP scheme.
        self.vdg_resolve_endpoint.set_scheme(http_scheme).unwrap();

        let did_resolver = did_webplus_resolver::DIDResolverThin {
            vdg_resolve_endpoint: self.vdg_resolve_endpoint,
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
