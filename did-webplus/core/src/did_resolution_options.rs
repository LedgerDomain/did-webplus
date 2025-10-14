/// A metadata structure containing properties defined in 7.1.1 DID Resolution Options.
/// This input is REQUIRED, but the structure MAY be empty.
///
/// See <https://www.w3.org/TR/did-1.0/#did-resolution> and
/// <https://www.w3.org/TR/did-1.0/#did-resolution-options>.
///
/// Populating DIDDocumentMetadata during DID resolution may incur network operations and DB queries.  The
/// various fields specify which parts of DIDDocumentMetadata are desired, and `local_resolution_only`
/// specifies if resolution is limited to locally-known data only.  Note that in some cases, certain
/// metadata can't be resolved locally, and in those cases, if `local_resolution_only` is true, then
/// resolution will return with error.  If a specific piece of metadata is not going to be used, then
/// there's no reason to incur the extra network/DB activity to determine it.
#[derive(Clone, Debug, Default, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDResolutionOptions {
    /// The Media Type of the caller's preferred representation of the DID document. The
    /// Media Type MUST be expressed as an ASCII string. The DID resolver implementation
    /// SHOULD use this value to determine the representation contained in the returned
    /// didDocumentStream if such a representation is supported and available. This
    /// property is OPTIONAL for the resolveRepresentation function and MUST NOT be
    /// used with the resolve function.
    ///
    /// did:webplus-specific note: This parameter is ignored.  The DID document is returned
    /// exactly as it is in its self-hashed form, meaning in JCS.  It is not altered in any
    /// way by puny media type request!
    #[serde(rename = "accept", default, skip_serializing_if = "Option::is_none")]
    pub accept_o: Option<String>,
    /// If true, attempt to populate the creation metadata, subject to the local_resolution_only flag.
    /// If omitted, defaults to false.
    #[serde(rename = "requestCreate", default)]
    pub request_creation: bool,
    /// If true, attempt to populate the next update metadata, subject to the local_resolution_only flag.
    /// If omitted, defaults to false.
    #[serde(rename = "requestNext", default)]
    pub request_next: bool,
    /// If true, attempt to populate the latest update metadata, subject to the local_resolution_only flag.
    /// If omitted, defaults to false.
    #[serde(rename = "requestLatest", default)]
    pub request_latest: bool,
    /// If true, attempt to populate the deactivated metadata, subject to the local_resolution_only flag.
    /// If omitted, defaults to false.
    #[serde(rename = "requestDeactivated", default)]
    pub request_deactivated: bool,
    /// If true, then no network requests will be made in the process of resolving the DID document
    /// and DID document metadata.  Note that this means that some cases may not be resolvable,
    /// and in those situations, will return an error.  If omitted, defaults to false (i.e. network
    /// requests will be allowed).
    #[serde(rename = "localResolutionOnly", default)]
    pub local_resolution_only: bool,
}

impl DIDResolutionOptions {
    pub fn all_metadata(local_resolution_only: bool) -> Self {
        Self {
            accept_o: None,
            request_creation: true,
            request_next: true,
            request_latest: true,
            request_deactivated: true,
            local_resolution_only,
        }
    }
    pub fn no_metadata(local_resolution_only: bool) -> Self {
        Self {
            accept_o: None,
            request_creation: false,
            request_next: false,
            request_latest: false,
            request_deactivated: false,
            local_resolution_only,
        }
    }
}
