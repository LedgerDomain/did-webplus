use crate::{LogFormat, Result, init_logging};
use std::sync::Arc;

/// Runs an HTTP server that resolve DID queries, using the did:webplus "Full" DID Resolver.
/// Queries can include query parameters for resolving DID documents of specific versions or
/// self-hash values.  This is the main entry point for the universal resolver driver.
#[derive(Debug, clap::Parser)]
pub struct Listen {
    /// The URL of the database to use.  Defaults to "sqlite://:memory:" for an in-memory SQLite database.
    /// Must start with "postgres://" or "sqlite://".  The postgres backend is only available if the
    /// "postgres" feature was enabled when this binary was built.
    #[arg(
        short,
        long,
        env = "DID_WEBPLUS_URD_DATABASE_URL",
        default_value = "sqlite://:memory:"
    )]
    pub database_url: String,
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
    /// The port to listen on.  Defaults to 80.
    #[arg(long, env = "DID_WEBPLUS_URD_LISTEN_PORT", default_value = "80")]
    pub listen_port: u16,
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
}

impl Listen {
    pub async fn handle(self) -> Result<()> {
        init_logging(self.log_format);

        // Create the DID resolver using the specified options.
        let did_resolver_full = did_webplus_urd_lib::create_did_resolver_full(
            &self.database_url,
            Some(self.http_scheme_override),
        )
        .await?;

        // Spawn the URD, returning a JoinHandle to the task.
        let urd_join_handle =
            did_webplus_urd_lib::spawn_urd(Arc::new(did_resolver_full), self.listen_port).await?;
        // Join the task by awaiting it.
        urd_join_handle.await?;

        Ok(())
    }
}
