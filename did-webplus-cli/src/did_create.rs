use crate::Result;

/// Create a DID hosted by a given VDR.
#[derive(clap::Parser)]
pub struct DIDCreate {
    /// Specify the URL of the VDR to use for DID creation.  If the URL's scheme is omitted, then "https" will be used.
    /// A scheme of "http" is only allowed if the host is "localhost".  The URL must not contain a query string or fragment.
    #[arg(name = "vdr", short, long, value_name = "URL")]
    pub vdr_url: url::Url,
}

impl DIDCreate {
    pub async fn handle(self) -> Result<()> {
        unimplemented!();
    }
}
