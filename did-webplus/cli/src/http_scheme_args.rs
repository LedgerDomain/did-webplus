// TODO: Potentially override http scheme on a host-by-host basis.
#[derive(clap::Args, Debug)]
pub struct HTTPSchemeArgs {
    /// Optionally override the HTTP scheme used for all HTTP requests.  Must either be "https" or "http".
    /// The value "http" should only be used for testing and development.
    #[arg(
        name = "http-scheme-override",
        env = "DID_WEBPLUS_HTTP_SCHEME_OVERRIDE",
        long,
        default_value = "https"
    )]
    pub http_scheme_override: String,
}

impl HTTPSchemeArgs {
    pub fn determine_http_scheme(&self) -> &'static str {
        match self.http_scheme_override.as_str() {
            "http" => "http",
            "https" => "https",
            _ => panic!(
                "Invalid HTTP scheme {:?} -- must be \"http\" or \"https\"",
                self.http_scheme_override
            ),
        }
    }
}
