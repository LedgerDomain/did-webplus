use crate::DIDResolveFull;
use crate::{DIDResolveThin, Result};

/// DID resolution operations.
#[derive(clap::Subcommand)]
pub enum DIDResolve {
    Full(DIDResolveFull),
    Thin(DIDResolveThin),
}

impl DIDResolve {
    pub async fn handle(self) -> Result<()> {
        match self {
            DIDResolve::Full(x) => x.handle().await,
            DIDResolve::Thin(x) => x.handle().await,
        }
    }
}

// use core::panic;

// use crate::{did_resolve_args::ResolverType, DIDResolveArgs, Result, REQWEST_CLIENT};

// /// Perform DID resolution for a given query URI.
// #[derive(Debug, clap::Parser)]
// pub struct DIDResolve {
//     /// The DID query URI to be resolved.  Examples:
//     /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ`,
//     /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?versionId=1`,
//     /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY`,
//     /// `did:webplus:example.com:EjXivDidxAi2kETdFw1o36-jZUkYkxg0ayMhSBjODAgQ?selfHash=EgqvDOcj4HItWDVij-yHj0GtBPnEofatHT2xuoVD7tMY&versionId=1`.
//     /// Note that the & character typically must be within a quoted string in a shell command.
//     pub did_query: String,
//     #[clap(flatten)]
//     pub resolve_args: DIDResolveArgs,
// }

// impl DIDResolve {
//     pub async fn handle(self) -> Result<()> {
//         tracing::debug!("{:?}", self);
//         let did_document = match self.resolve_args.resolver {
//             ResolverType::Full => self.resolve_full().await?,
//             ResolverType::Thin => self.resolve_thin().await?,
//         };
//         println!("{}", did_document);
//         Ok(())
//     }
//     async fn resolve_full(self) -> Result<String> {
//         let database_url = std::env::var("DID_WEBPLUS_")
//     }
//     async fn resolve_thin(self) -> Result<String> {
//         if self.resolve_args.vdg_resolve_endpoint_o.is_none() {
//             panic!("the --vdg argument is required if --thin is specified");
//         }
//         let mut vdg_resolve_endpoint = self.resolve_args.vdg_resolve_endpoint_o.unwrap();
//         match vdg_resolve_endpoint.scheme() {
//             "https" => {}
//             "http" => {
//                 if vdg_resolve_endpoint.host_str().is_none()
//                     || vdg_resolve_endpoint.host_str().as_deref().unwrap() != "localhost"
//                 {
//                     panic!("VDG resolve endpoint may only use http with localhost");
//                 }
//             }
//             "" => {
//                 vdg_resolve_endpoint.set_scheme("https").unwrap();
//             }
//             _ => {
//                 panic!("VDG resolve endpoint must use either http or https");
//             }
//         }
//         if !vdg_resolve_endpoint.path().ends_with('/') {
//             panic!("VDG resolve endpoint must end with a slash");
//         }
//         if vdg_resolve_endpoint.query().is_some() {
//             panic!("VDG resolve endpoint must not contain a query string");
//         }
//         if vdg_resolve_endpoint.fragment().is_some() {
//             panic!("VDG resolve endpoint must not contain a fragment");
//         }
//         tracing::debug!("VDG resolve endpoint: {}", vdg_resolve_endpoint);
//         let resolution_url = {
//             let did_query_url_encoded = temp_hack_incomplete_url_encoded(self.did_query.as_str());
//             let mut path = vdg_resolve_endpoint.path().to_string();
//             assert!(path.ends_with('/'));
//             path.push_str(did_query_url_encoded.as_str());
//             let mut resolution_url = vdg_resolve_endpoint;
//             resolution_url.set_path(path.as_str());
//             tracing::debug!("DID resolution URL: {}", resolution_url);
//             resolution_url
//         };
//         let response = REQWEST_CLIENT
//             .get(resolution_url)
//             .send()
//             .await?
//             .error_for_status()?;
//         let did_document = response.text().await?;
//         Ok(did_document)
//     }
// }
