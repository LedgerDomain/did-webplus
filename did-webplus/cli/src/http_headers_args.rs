#[derive(clap::Args, Debug)]
pub struct HTTPHeadersArgs {
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
}
