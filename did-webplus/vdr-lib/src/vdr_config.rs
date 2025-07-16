#[derive(clap::Args, Clone, Debug)]
pub struct VDRConfig {
    /// Specify the hostname that appears in DIDs hosted by this VDR, i.e. hostname "example.com"
    /// for DIDs `did:webplus:example.com:xyz`.  This does not include the scheme or the port.
    #[arg(env = "DID_WEBPLUS_VDR_DID_HOSTNAME", long, value_name = "HOST")]
    pub did_hostname: String,
    /// Optionally specify a non-standard port for use in the hosted DIDs themselves.  They appear as
    /// `did:webplus:<hostname>%3A<port>:<...>`.  This is different than the port on which the VDR
    /// listens for requests.
    #[arg(
        name = "did-port",
        env = "DID_WEBPLUS_VDR_DID_PORT",
        long,
        value_name = "PORT"
    )]
    pub did_port_o: Option<u16>,
    /// Specify the port on which the service will listen for HTTP requests.
    #[arg(
        env = "DID_WEBPLUS_VDR_LISTEN_PORT",
        long,
        value_name = "PORT",
        default_value = "80"
    )]
    pub listen_port: u16,
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
    /// Specify the comma-separated list of the VDG hosts (in the form `<hostname>` or
    /// `<hostname>:<port>`) to notify of each DID update.  An empty list means that no
    /// notifications will be sent.  Note that the scheme used for update operations will
    /// be "https" in general, and "http" for localhost, unless the --http-scheme-override
    /// argument is used.
    // NOTE: It's critical that the type of gateways be fully qualified as `std::vec::Vec<url::Url>`;
    // see https://github.com/clap-rs/clap/issues/4481#issuecomment-1314475143
    #[arg(
        env = "DID_WEBPLUS_VDR_GATEWAY_HOSTS",
        long,
        value_name = "URLs",
        default_value = "",
        value_parser = parse_comma_separated_hosts_into_urls,
    )]
    pub gateway_url_v: std::vec::Vec<url::Url>,
    /// Optionally specify a comma-separated list of `hostname=scheme` pairs defining the scheme to use
    /// for each of the specified hostnames when the VDR connects to VDGs to notify of updated DIDs.
    /// This particular mechanic is unrelated to DID resolution, and is specific to did:webplus
    /// VDR-to-VDG communication.
    #[arg(
        name = "http-scheme-override",
        env = "DID_WEBPLUS_VDR_HTTP_SCHEME_OVERRIDE",
        long,
        default_value = "",
        value_parser = did_webplus_core::HTTPSchemeOverride::parse_from_comma_separated_pairs
    )]
    pub http_scheme_override: did_webplus_core::HTTPSchemeOverride,
}

fn parse_comma_separated_hosts_into_urls(s: &str) -> anyhow::Result<Vec<url::Url>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let gateway_url_v = s
        .split(',')
        .map(|host| {
            // Apply "https" as the default scheme, then set it to "http" if the hostname is "localhost".
            let mut url = url::Url::parse(&format!("https://{}", host))?;
            if url.host_str().unwrap() == "localhost" {
                url.set_scheme("http").unwrap();
            }
            Ok(url)
        })
        .collect::<Result<Vec<url::Url>, url::ParseError>>()?;
    Ok(gateway_url_v)
}
