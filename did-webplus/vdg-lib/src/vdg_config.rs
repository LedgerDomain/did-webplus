#[derive(clap::Args, Clone, Debug)]
pub struct VDGConfig {
    /// Specify the domain of the service, e.g. "example.com".  This does not include the scheme or the port.
    #[arg(
        name = "service-domain",
        env = "DID_WEBPLUS_VDG_SERVICE_DOMAIN",
        long,
        value_name = "DOMAIN"
    )]
    pub service_domain: String,
    /// Specify the port on which the service will listen for HTTP requests.
    #[arg(
        name = "port",
        env = "DID_WEBPLUS_VDG_PORT",
        long,
        default_value = "80"
    )]
    pub port: u16,
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
}
