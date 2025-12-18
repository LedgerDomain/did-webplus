use crate::{
    DIDResolutionOptionsArgs, DIDResolverArgs, HTTPHeadersArgs, HTTPSchemeOverrideArgs,
    NewlineArgs, Result,
};
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
    pub did_resolution_options_args: DIDResolutionOptionsArgs,
    #[command(flatten)]
    pub http_headers_args: HTTPHeadersArgs,
    #[command(flatten)]
    pub http_scheme_override_args: HTTPSchemeOverrideArgs,
    /// If true, print the DID document, DID document metadata, and DID resolution metadata as JSON to stdout.
    /// Otherwise, print the DID document, DID document metadata, and DID resolution metadata as JSON to stderr,
    /// and print the DID document as a string to stdout.
    #[arg(
        name = "json",
        env = "DID_WEBPLUS_RESOLVE_AS_JSON",
        short = 'j',
        long,
        default_value = "false"
    )]
    pub json: bool,
    #[command(flatten)]
    pub newline_args: NewlineArgs,
}

impl DIDResolve {
    pub async fn handle(self) -> Result<()> {
        // Handle CLI args and input

        let http_options_o = Some(did_webplus_core::HTTPOptions {
            http_headers_for: self.http_headers_args.http_headers_for.clone(),
            http_scheme_override: self.http_scheme_override_args.http_scheme_override.clone(),
        });
        let did_resolver_b = self
            .did_resolver_args
            .get_did_resolver(http_options_o)
            .await?;
        let did_resolution_options = self
            .did_resolution_options_args
            .get_did_resolution_options();

        // Do the processing
        let (did_document_string, did_document_metadata, did_resolution_metadata) =
            did_webplus_cli_lib::did_resolve_string(
                &self.did_query,
                did_resolver_b.as_ref(),
                did_resolution_options,
            )
            .await?;

        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct DIDResolveOutput {
            did_document: String,
            did_document_metadata: did_webplus_core::DIDDocumentMetadata,
            did_resolution_metadata: did_webplus_core::DIDResolutionMetadata,
        }
        let output = DIDResolveOutput {
            did_document: did_document_string.clone(),
            did_document_metadata,
            did_resolution_metadata,
        };

        if self.json {
            serde_json::to_writer_pretty(&mut std::io::stdout(), &output)?;
            self.newline_args
                .print_newline_if_necessary(&mut std::io::stdout())?;
        } else {
            // Print the DID document, DID document metadata, and DID resolution metadata as JSON to stderr.
            serde_json::to_writer_pretty(&mut std::io::stderr(), &output)?;
            std::io::stderr().write_all(b"\n")?;

            // Print the DID document string, then optional newline.
            std::io::stdout().write_all(did_document_string.as_bytes())?;
            self.newline_args
                .print_newline_if_necessary(&mut std::io::stdout())?;
        }

        Ok(())
    }
}
