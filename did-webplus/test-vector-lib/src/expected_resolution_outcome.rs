/// Expected result of one [`crate::ResolutionStep`] against a full resolver.
///
/// Normative for harnesses:
/// - [`Self::success`]
/// - On success: [`Self::did_document_version_id_o`], [`Self::did_document_self_hash_o`],
///   and byte-exact [`Self::did_document_metadata_o`] (literal timestamps; generation
///   is deterministic so these are concrete values)
/// - Exact DID resolution metadata booleans in [`Self::did_resolution_metadata`]
///   (`fetchedUpdatesFromVDR`, `didDocumentResolvedLocally`,
///   `didDocumentMetadataResolvedLocally`)
/// - [`Self::vdr_request_count`] — `0` proves local-only / no VDR contact; `1`
///   proves a single Range fetch
///
/// On failure (`success == false`): harnesses MUST assert that
/// `did_resolution_metadata.error` is present; the error message text is advisory
/// and need not match. Success-only document fields are omitted (`None`).
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedResolutionOutcome {
    /// `true` when resolution must succeed; `false` when it must fail with an error.
    pub success: bool,
    /// `versionId` of the resolved DID document; present iff [`Self::success`].
    #[serde(
        rename = "didDocumentVersionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub did_document_version_id_o: Option<u32>,
    /// `selfHash` of the resolved DID document; present iff [`Self::success`].
    #[serde(
        rename = "didDocumentSelfHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub did_document_self_hash_o: Option<mbx::MBHash>,
    /// Exact DID document metadata; present iff [`Self::success`].
    ///
    /// Reuses [`did_webplus_core::DIDDocumentMetadata`] for wire-exact JSON
    /// (including millisecond timestamp fields).
    #[serde(
        rename = "didDocumentMetadata",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub did_document_metadata_o: Option<did_webplus_core::DIDDocumentMetadata>,
    /// DID resolution metadata expectations.
    ///
    /// The three booleans are normative. On error, `error` is asserted present-only
    /// (message advisory). `contentType` is typically `"application/did+json"`.
    pub did_resolution_metadata: did_webplus_core::DIDResolutionMetadata,
    /// Exact number of HTTP requests to this DID's `did-documents.jsonl` during
    /// the step.
    pub vdr_request_count: u32,
}

impl ExpectedResolutionOutcome {
    /// Build a successful outcome with the given document identity, metadata, and
    /// VDR request count.
    pub fn success(
        did_document_version_id: u32,
        did_document_self_hash: mbx::MBHash,
        did_document_metadata: did_webplus_core::DIDDocumentMetadata,
        did_resolution_metadata: did_webplus_core::DIDResolutionMetadata,
        vdr_request_count: u32,
    ) -> Self {
        Self {
            success: true,
            did_document_version_id_o: Some(did_document_version_id),
            did_document_self_hash_o: Some(did_document_self_hash),
            did_document_metadata_o: Some(did_document_metadata),
            did_resolution_metadata,
            vdr_request_count,
        }
    }

    /// Build a failing outcome. `did_resolution_metadata.error` should be `Some`;
    /// harnesses treat the message as advisory.
    pub fn failure(
        did_resolution_metadata: did_webplus_core::DIDResolutionMetadata,
        vdr_request_count: u32,
    ) -> Self {
        Self {
            success: false,
            did_document_version_id_o: None,
            did_document_self_hash_o: None,
            did_document_metadata_o: None,
            did_resolution_metadata,
            vdr_request_count,
        }
    }
}
