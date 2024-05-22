use crate::Result;

/// Create a DID hosted by a given VDR.  For now (temp hack for simplicity), it will use a single key for all key purposes.
#[derive(clap::Parser)]
pub struct DIDCreate {
    /// Specify the URL of the VDR to use for DID creation.  If the URL's scheme is omitted, then "https" will be used.
    /// A scheme of "http" is only allowed if the host is "localhost".  The URL must not contain a query string or fragment.
    #[arg(name = "vdr", short, long, value_name = "URL")]
    pub vdr_create_endpoint: url::Url,
}

impl DIDCreate {
    pub async fn handle(self) -> Result<()> {
        // let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        // let verifying_key = signing_key.verifying_key();
        unimplemented!();
    }
}
