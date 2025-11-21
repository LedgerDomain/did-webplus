#[derive(clap::Args, Clone, Debug)]
pub struct DIDResolutionOptionsArgs {
    /// If true, attempt to populate the creation metadata, subject to the --local-resolution-only flag.
    /// If omitted, defaults to false (it requires more queries, so it is opt-in).
    #[arg(
        name = "creation",
        env = "DID_WEBPLUS_REQUEST_CREATION",
        short = 'C',
        long,
        default_value = "false"
    )]
    pub request_creation: bool,
    /// If true, attempt to populate the next update metadata, subject to the --local-resolution-only flag.
    /// If omitted, defaults to false (it requires more queries, so it is opt-in).
    #[arg(
        name = "next",
        env = "DID_WEBPLUS_REQUEST_NEXT",
        short = 'N',
        long,
        default_value = "false"
    )]
    pub request_next: bool,
    /// If true, attempt to populate the latest update metadata, subject to the --local-resolution-only flag.
    /// If omitted, defaults to false (it requires more queries, so it is opt-in).
    #[arg(
        name = "latest",
        env = "DID_WEBPLUS_REQUEST_LATEST",
        short = 'L',
        long,
        default_value = "false"
    )]
    pub request_latest: bool,
    /// If true, attempt to populate the deactivated metadata, subject to the --local-resolution-only flag.
    /// If omitted, defaults to false (it requires more queries, so it is opt-in).
    #[arg(
        name = "deactivated",
        env = "DID_WEBPLUS_REQUEST_DEACTIVATED",
        short = 'D',
        long,
        default_value = "false"
    )]
    pub request_deactivated: bool,
    /// If true, then DID resolution will be attempted purely from locally-known data; no network requests
    /// will be made in the process of resolving the DID document and DID document metadata.  Note that
    /// this means that some cases may not be resolvable, and in those situations, will return an error.
    /// If omitted, defaults to false (i.e. network requests will be allowed).
    #[arg(
        name = "local-resolution-only",
        env = "DID_WEBPLUS_LOCAL_RESOLUTION_ONLY",
        short = 'l',
        long,
        default_value = "false"
    )]
    pub local_resolution_only: bool,
}

impl DIDResolutionOptionsArgs {
    pub fn get_did_resolution_options(self) -> did_webplus_core::DIDResolutionOptions {
        did_webplus_core::DIDResolutionOptions {
            accept_o: None,
            request_creation: self.request_creation,
            request_next: self.request_next,
            request_latest: self.request_latest,
            request_deactivated: self.request_deactivated,
            local_resolution_only: self.local_resolution_only,
        }
    }
}
