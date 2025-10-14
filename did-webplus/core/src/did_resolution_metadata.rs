/// See <https://www.w3.org/TR/did-1.0/#did-resolution-metadata>.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct DIDResolutionMetadata {
    /// The Media Type of the returned didDocumentStream. This property is REQUIRED if resolution
    /// is successful and if the resolveRepresentation function was called. This property MUST NOT
    /// be present if the resolve function was called. The value of this property MUST be an ASCII
    /// string that is the Media Type of the conformant representations. The caller of the
    /// resolveRepresentation function MUST use this value when determining how to parse and
    /// process the didDocumentStream returned by this function into the data model.
    #[serde(
        rename = "contentType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type_o: Option<String>,
    /// The error code from the resolution process. This property is REQUIRED when there is an
    /// error in the resolution process. The value of this property MUST be a single keyword
    /// ASCII string. The possible property values of this field SHOULD be registered in the
    /// DID Specification Registries <https://www.w3.org/TR/did-spec-registries/>.
    #[serde(rename = "error", default, skip_serializing_if = "Option::is_none")]
    pub error_o: Option<String>,
    /// This will be `true` if the resolution process involved attempting to fetch updates from the
    /// VDR for the DID, even if there were no new updates returned by the VDR.  Otherwise `false`.
    #[serde(rename = "fetchedUpdatesFromVDR")]
    pub fetched_updates_from_vdr: bool,
    /// This will be `true` if the resolved DID document was already present in the local DID document store.
    /// Otherwise `false`.  Note that this and fetched_updates_from_vdr can be true simultaneously if
    /// metadata was requested that required fetching updates from VDR.
    #[serde(rename = "didDocumentResolvedLocally")]
    pub did_document_resolved_locally: bool,
    /// This will be `true` if the data necessary to produce the DID document metadata was already present
    /// in the local DID document store.  Otherwise `false`.
    #[serde(rename = "didDocumentMetadataResolvedLocally")]
    pub did_document_metadata_resolved_locally: bool,
}

impl std::fmt::Display for DIDResolutionMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
