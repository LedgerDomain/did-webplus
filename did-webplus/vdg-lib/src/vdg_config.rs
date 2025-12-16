#[derive(clap::Args, Clone, Debug)]
pub struct VDGConfig {
    /// Specify the port on which the service will listen for HTTP requests.
    #[arg(env = "DID_WEBPLUS_VDG_LISTEN_PORT", long, default_value = "80")]
    pub listen_port: u16,
    /// Specify the URL of the database to connect to, e.g. "postgres:///database-name", "sqlite://name.db",
    /// "sqlite://name.db?mode=rwc" (read+write, create if it doesn't yet exist).
    /// See https://docs.rs/sqlx/latest/sqlx/postgres/struct.PgConnectOptions.html and
    /// https://docs.rs/sqlx/latest/sqlx/sqlite/struct.SqliteConnectOptions.html for more details.
    /// Note that the `postgres` and `sqlite` cargo features must be enabled, respectively, in order
    /// to support each database type.
    #[arg(
        name = "database-url",
        env = "DID_WEBPLUS_VDG_DATABASE_URL",
        long,
        value_name = "URL"
    )]
    pub database_url: String,
    /// Specify the maximum number of connections to the database.
    #[arg(
        name = "database-max-connections",
        env = "DID_WEBPLUS_VDG_DATABASE_MAX_CONNECTIONS",
        long,
        default_value = "10"
    )]
    pub database_max_connections: u32,
    /// Optionally specify a semicolon-separated list of comma-separated list of `name=value` pairs
    /// defining the HTTP headers to use for each of the specified hosts.  This would be used in the
    /// a VDG if it were a proxy for another VDG.
    #[arg(
        name = "http-headers-for",
        env = "DID_WEBPLUS_HTTP_HEADERS_FOR",
        long,
        default_value = "",
        value_parser = did_webplus_core::HTTPHeadersFor::parse_from_semicolon_separated_pairs,
    )]
    pub http_headers_for: did_webplus_core::HTTPHeadersFor,
    /// Optionally specify a comma-separated list of `hostname=scheme` pairs defining the scheme to use
    /// for each of the specified hosts when the VDG connects to VDRs to resolve DIDs.  The default
    /// did:webplus resolution rules specify that localhost uses the "http" scheme, and everything
    /// else uses the "https" scheme.  This argument can be used to override this behavior for specific
    /// hosts.  Besides localhost, the "http" scheme should only be used for testing and development.
    #[arg(
        name = "http-scheme-override",
        env = "DID_WEBPLUS_VDG_HTTP_SCHEME_OVERRIDE",
        long,
        default_value = "",
        value_parser = did_webplus_core::HTTPSchemeOverride::parse_from_comma_separated_pairs
    )]
    pub http_scheme_override: did_webplus_core::HTTPSchemeOverride,
    /// Optionally specify a set of values to check against the "x-api-key" HTTP header value of requests
    /// in order to check authorization for the HTTP requests that mediate DID creation and update operations.
    /// If the "x-api-key" HTTP header value is not present in the request, or is present but does not match
    /// any of the specified values, then the request is rejected.  The /webplus/v1/update endpoint is not
    /// authorization-protected.  If this is set, then the VDG will perform this authorization check.  If
    /// not set, no authorization check will be done.  This is a very coarse grained mechanism meant to
    /// be used only for testing and development.  Real authorization checks should be done via reverse
    /// proxy or similar mechanism.
    #[arg(
        name = "test-authz-api-keys",
        env = "DID_WEBPLUS_VDG_TEST_AUTHZ_API_KEYS",
        long,
        value_name = "API_KEYS",
        default_value = "",
        value_parser = parse_comma_separated_api_keys_into_strings,
    )]
    pub test_authz_api_key_vo: Option<Vec<String>>,
}

fn parse_comma_separated_api_keys_into_strings(s: &str) -> anyhow::Result<Option<Vec<String>>> {
    let s = s.trim();
    if s.is_empty() {
        Ok(None)
    } else {
        let api_keys_v = s
            .split(',')
            .map(|api_key| api_key.trim().to_string())
            .collect::<Vec<String>>();
        Ok(Some(api_keys_v))
    }
}
