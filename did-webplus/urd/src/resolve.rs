use crate::{LogFormat, Result, init_logging};

/// Resolve a DID (potentially with query parameters), printing the DID document to stdout.
/// This subcommand exists mostly to be able to manually test/debug DID resolution separate from
/// the HTTP server provided by the `listen` subcommand.
// TODO: This is probably only a dev command to debug things.
#[derive(Debug, clap::Parser)]
pub struct Resolve {
    /// The URL of the database to use.  Defaults to ":memory:" for an in-memory database.
    #[arg(
        short,
        long,
        env = "DID_WEBPLUS_URD_DATABASE_URL",
        default_value = ":memory:"
    )]
    pub database_url: String,
    /// The host (host means hostname and optional port number) of the VDG to use for fetching DID
    /// documents.  This is used so that this resolver can take part in the scope of agreement defined
    /// by the VDG.  Without using a VDG, a "Full" DID resolver has a scope of agreement that only
    /// contains itself.
    #[arg(name = "vdg", long, env = "DID_WEBPLUS_URD_VDG", value_name = "HOST")]
    pub vdg_host_o: Option<String>,
    /// Optionally specify a semicolon-separated list of comma-separated list of `name=value` pairs
    /// defining the HTTP headers to use for each of the specified hosts.
    #[arg(
        name = "http-headers-for",
        env = "DID_WEBPLUS_HTTP_HEADERS_FOR",
        long,
        default_value = "",
        value_parser = did_webplus_core::HTTPHeadersFor::parse_from_semicolon_separated_pairs,
    )]
    pub http_headers_for: did_webplus_core::HTTPHeadersFor,
    /// Optionally specify a comma-separated list of `hostname=scheme` pairs defining the scheme to use
    /// for each of the specified hosts.  The default did:webplus resolution rules specify that
    /// localhost uses the "http" scheme, and everything else uses the "https" scheme.  This
    /// argument can be used to override this behavior for specific hostnames.  Besides localhost,
    /// the "http" scheme should only be used for testing and development.
    #[arg(
        name = "http-scheme-override",
        env = "DID_WEBPLUS_URD_HTTP_SCHEME_OVERRIDE",
        long,
        default_value = "",
        value_parser = did_webplus_core::HTTPSchemeOverride::parse_from_comma_separated_pairs,
    )]
    pub http_scheme_override: did_webplus_core::HTTPSchemeOverride,
    /// Specify the format of the logs.  "compact" produces one line per log message, while "pretty"
    /// produces verbose multi-line messages.
    #[arg(
        name = "log-format",
        env = "DID_WEBPLUS_URD_LOG_FORMAT",
        long,
        value_name = "FORMAT",
        default_value = "compact",
        value_enum
    )]
    pub log_format: LogFormat,
    /// The query string to resolve.  In particular, this could be a DID or a DID with query parameters.
    pub query: String,
}

impl Resolve {
    pub async fn handle(self) -> Result<()> {
        init_logging(self.log_format);

        let did_resolver_full = did_webplus_urd_lib::create_did_resolver_full(
            &self.database_url,
            self.vdg_host_o.as_deref(),
            Some(did_webplus_core::HTTPOptions {
                http_headers_for: self.http_headers_for,
                http_scheme_override: self.http_scheme_override,
            }),
        )
        .await?;
        use did_webplus_resolver::DIDResolver;
        let (did_document, _did_document_metadata, _did_resolution_metadata) = did_resolver_full
            .resolve_did_document_string(
                &self.query,
                did_webplus_core::DIDResolutionOptions::no_metadata(false),
            )
            .await?;
        print!("{}", did_document);
        Ok(())
    }
}
