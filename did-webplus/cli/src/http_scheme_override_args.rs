#[derive(clap::Args, Debug)]
pub struct HTTPSchemeOverrideArgs {
    /// Optionally specify a comma-separated list of `hostname=scheme` pairs defining the scheme to use
    /// for each of the specified hosts.  The default did:webplus resolution rules specify that
    /// localhost uses the "http" scheme, and everything else uses the "https" scheme.  This
    /// argument can be used to override this behavior for specific hostnames.  Besides localhost,
    /// the "http" scheme should only be used for testing and development.
    #[arg(
        name = "http-scheme-override",
        env = "DID_WEBPLUS_HTTP_SCHEME_OVERRIDE",
        long,
        default_value = "",
        value_parser = did_webplus_core::HTTPSchemeOverride::parse_from_comma_separated_pairs,
    )]
    pub http_scheme_override: did_webplus_core::HTTPSchemeOverride,
}
