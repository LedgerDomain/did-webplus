use crate::{determine_http_scheme, Result};

/// Perform DID resolution for a given query URI, using the "raw" resolution method, which only does
/// a limited subset of verification, so should not be used for any production purposes.  THIS IS
/// INTENDED ONLY FOR DEVELOPMENT AND TESTING PURPOSES.
#[derive(Debug, clap::Parser)]
pub struct DIDResolveRaw {
    /// The DID query URI to be resolved.  Examples:
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=1`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY&versionId=1`.
    /// Note that the & character typically must be within a quoted string in a shell command.
    pub did_query: String,
    // /// Specify the scheme to use for the VDR in the DID resolution request.  Must either be "http" or "https".
    // // TODO: Validation in clap derive for this constraint.
    // #[arg(short, long, value_name = "SCHEME", default_value = "https")]
    // pub vdr_scheme: String,
}

impl DIDResolveRaw {
    pub async fn handle(self) -> Result<()> {
        tracing::debug!("{:?}", self);

        let http_scheme = determine_http_scheme();

        // // This looks dumb, but it's to get a `&'static str` as required by Wallet::update_did.
        // let vdr_scheme = match self.vdr_scheme.as_str() {
        //     "http" => "http",
        //     "https" => "https",
        //     _ => {
        //         anyhow::bail!("--vdr-scheme argument must be \"http\" or \"https\"");
        //     }
        // };

        let did_resolution_url = if let Ok(did_fully_qualified) =
            did_webplus::DIDFullyQualifiedStr::new_ref(self.did_query.as_str())
        {
            did_fully_qualified.resolution_url(http_scheme)
        } else if let Ok(did) = did_webplus::DIDStr::new_ref(self.did_query.as_str()) {
            did.resolution_url(http_scheme)
        } else {
            anyhow::bail!("Invalid DID query: {}", self.did_query);
        };

        let response = crate::REQWEST_CLIENT
            .get(did_resolution_url)
            .send()
            .await?
            .error_for_status()?;
        let did_document = response.text().await?;
        println!("{}", did_document);
        Ok(())
    }
}
