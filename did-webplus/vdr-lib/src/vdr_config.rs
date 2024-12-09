#[derive(clap::Args, Clone, Debug)]
pub struct VDRConfig {
    /// Specify the domain of the service, e.g. "example.com".  This does not include the scheme or the port.
    #[arg(env = "DID_WEBPLUS_VDR_SERVICE_DOMAIN", long, value_name = "DOMAIN")]
    pub service_domain: String,
    /// Specify the port on which the service will listen for HTTP requests.
    #[arg(
        env = "DID_WEBPLUS_VDR_PORT",
        long,
        value_name = "PORT",
        default_value = "80"
    )]
    pub port: u16,
    /// Specify the URL of the database to connect to, e.g. "postgres:///database-name", "sqlite://name.db",
    /// "sqlite://name.db?mode=rwc" (read+write, create if it doesn't yet exist).
    /// See https://docs.rs/sqlx/latest/sqlx/postgres/struct.PgConnectOptions.html and
    /// https://docs.rs/sqlx/latest/sqlx/sqlite/struct.SqliteConnectOptions.html for more details.
    /// Note that the `postgres` and `sqlite` cargo features must be enabled, respectively, in order
    /// to support each database type.
    #[arg(env = "DID_WEBPLUS_VDR_DATABASE_URL", long, value_name = "URL")]
    pub database_url: String,
    /// Specify the maximum number of connections to the database.
    #[arg(
        name = "database-max-connections",
        env = "DID_WEBPLUS_VDR_DATABASE_MAX_CONNECTIONS",
        long,
        value_name = "CONNECTIONS",
        default_value = "10"
    )]
    pub database_max_connections: u32,
    /// Specify the comma-separated list of the URLs of the VDGs to notify of each DID update.
    /// An empty list means that no notifications will be sent.
    // NOTE: It's critical that the type of gateways be fully qualified as `std::vec::Vec<String>`;
    // see https://github.com/clap-rs/clap/issues/4481#issuecomment-1314475143
    #[arg(
        env = "DID_WEBPLUS_VDR_GATEWAYS",
        long,
        value_name = "URLs",
        default_value = "",
        value_parser = parse_comma_separated_urls,
    )]
    pub gateways: std::vec::Vec<String>,
}

fn parse_comma_separated_urls(s: &str) -> anyhow::Result<Vec<String>> {
    if s.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(s.split(',').map(|s| s.to_string()).collect())
    }
}
