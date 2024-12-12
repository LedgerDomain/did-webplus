#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum HTTPScheme {
    HTTP,
    HTTPS,
}

impl HTTPScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            HTTPScheme::HTTP => "http",
            HTTPScheme::HTTPS => "https",
        }
    }
}

// TODO: Potentially override http scheme on a host-by-host basis.
#[derive(clap::Args, Debug)]
pub struct HTTPSchemeArgs {
    /// Optionally override the HTTP scheme used for all HTTP requests.  The value "http" should only
    /// be used for testing and development.
    #[arg(
        name = "http-scheme-override",
        env = "DID_WEBPLUS_HTTP_SCHEME_OVERRIDE",
        long,
        default_value = "https"
    )]
    pub http_scheme_override: HTTPScheme,
}

impl HTTPSchemeArgs {
    pub fn determine_http_scheme(&self) -> &'static str {
        self.http_scheme_override.as_str()
    }
}
