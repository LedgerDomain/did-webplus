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
}
