/// This data is not immutable, but may only be changed by appending a new DID document, and
/// therefore may only be changed once.  Furthermore, the changes are "monotonic" in the sense that
/// optional fields may be set, but not unset, and the values of existing fields can not be changed.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DIDDocumentMetadata {
    /// This is when the DID was initially created.
    pub created: chrono::DateTime<chrono::Utc>,

    // NOTE: This is commented out because it only introduces a redundancy that has to be verified.
    // /// This is the hash of this DID document.
    // pub did_document_hash: String,
    /// If there is a DID document following this one, then this is equal to its valid_from value.
    /// Otherwise, this is the most recent DID document for this DID, and this field is None.
    pub valid_until_o: Option<chrono::DateTime<chrono::Utc>>,
}
