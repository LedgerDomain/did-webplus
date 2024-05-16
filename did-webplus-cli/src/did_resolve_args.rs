#[derive(Copy, Clone, Debug)]
pub enum ResolverType {
    Full,
    Thin,
}

impl std::fmt::Display for ResolverType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ResolverType::Full => write!(f, "full"),
            ResolverType::Thin => write!(f, "thin"),
        }
    }
}

impl std::str::FromStr for ResolverType {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "full" => Ok(ResolverType::Full),
            "thin" => Ok(ResolverType::Thin),
            _ => Err("Resolver type must be either 'full' or 'thin'"),
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct DIDResolveArgs {
    /// Specifies if "full" DID resolution process should be performed, as opposed to "thin" resolution.
    /// "Full" means that all fetching, verification, and caching of DID documents will happen locally
    /// and therefore not rely on a trusted external service (VDG).  "Thin" means that the resolution
    /// process will rely on a trusted external service (VDG) do perform the DID resolution process,
    /// and only the final DID document will be returned.
    #[arg(short, long)]
    pub resolver: ResolverType,
    /// Specify the URL of the "resolve" endpoint of the VDG to use for DID resolution.  This is required
    /// if the "thin" resolver is used, and is optional if the "full" resolver is used.  If the URL's
    /// scheme is omitted, then "https" will be used.  A scheme of "http" is only allowed if the host
    /// is "localhost".  The URL must not contain a query string or fragment.
    #[arg(name = "vdg", short, long, value_name = "URL")]
    pub vdg_resolve_endpoint_o: Option<url::Url>,
}
