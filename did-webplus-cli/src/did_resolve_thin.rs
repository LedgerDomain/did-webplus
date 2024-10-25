use crate::{determine_http_scheme, parse_url, temp_hack_incomplete_url_encoded, Result};

/// Perform DID resolution for a given query URI, using the "thin" resolver, relying on a VDG
/// (Verifiable Data Gateway) to perform fetching, validation, and storage.  This is useful
/// for clients that can't or do not want to implement the full DID resolution logic themselves.
#[derive(Debug, clap::Parser)]
pub struct DIDResolveThin {
    /// The DID query URI to be resolved.  Examples:
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=1`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY`,
    /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY&versionId=1`.
    /// Note that the & character typically must be within a quoted string in a shell command.
    pub did_query: String,
    /// Specify the URL of the "resolve" endpoint of the VDG to use for DID resolution.  The URL can
    /// omit the scheme (i.e. the "https://" portion).  The URL must not contain a query string
    /// or fragment.
    #[arg(
        name = "vdg",
        env = "DID_WEBPLUS_VDG",
        short,
        long,
        value_name = "URL",
        value_parser = parse_url,
    )]
    pub vdg_resolve_endpoint: url::Url,
}

impl DIDResolveThin {
    pub async fn handle(mut self) -> Result<()> {
        tracing::debug!("{:?}", self);

        let http_scheme = determine_http_scheme();

        // Override HTTP scheme.
        self.vdg_resolve_endpoint.set_scheme(http_scheme).unwrap();
        if !self.vdg_resolve_endpoint.path().ends_with('/') {
            panic!("VDG resolve endpoint must end with a slash");
        }
        if self.vdg_resolve_endpoint.query().is_some() {
            panic!("VDG resolve endpoint must not contain a query string");
        }
        if self.vdg_resolve_endpoint.fragment().is_some() {
            panic!("VDG resolve endpoint must not contain a fragment");
        }
        tracing::debug!("VDG resolve endpoint: {}", self.vdg_resolve_endpoint);
        let resolution_url = {
            let did_query_url_encoded = temp_hack_incomplete_url_encoded(self.did_query.as_str());
            let mut path = self.vdg_resolve_endpoint.path().to_string();
            assert!(path.ends_with('/'));
            path.push_str(did_query_url_encoded.as_str());
            let mut resolution_url = self.vdg_resolve_endpoint;
            resolution_url.set_path(path.as_str());
            tracing::debug!("DID resolution URL: {}", resolution_url);
            resolution_url
        };
        // TODO: Consolidate all the REQWEST_CLIENT-s
        let response = crate::REQWEST_CLIENT
            .get(resolution_url)
            .send()
            .await?
            .error_for_status()?;
        let did_document = response.text().await?;
        println!("{}", did_document);
        Ok(())
    }
}
