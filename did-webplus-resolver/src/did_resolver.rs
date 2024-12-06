use crate::{Error, Result};

#[async_trait::async_trait]
pub trait DIDResolver {
    /// This resolves the given DID, returning the DID document and its metadata.  The metadata
    /// is needed for determining the validity duration of a DID document so as to be able to
    /// determine if a signing key was active at a given time.  Only the metadata requested in
    /// the RequestedDIDDocumentMetadata struct will be returned.  Requesting less metadata may
    /// result in a faster resolution in some implementations of this trait, as some operations
    /// may be able to occur with fewer or no network operations, though the specifics depend
    /// on the implementation.
    // TODO: Also return a timestamp generated by the VDR (TODO: Figure out how this timestamp
    // works with a VDG).
    async fn resolve_did_document_string(
        &self,
        did_query: &str,
        requested_did_document_metadata: did_webplus::RequestedDIDDocumentMetadata,
    ) -> Result<(String, did_webplus::DIDDocumentMetadata)>;
    /// Convenience method.  This just calls into resolve_did_document_string and then deserializes
    /// the DID document string into a DIDDocument struct.
    async fn resolve_did_document(
        &self,
        did_query: &str,
        requested_did_document_metadata: did_webplus::RequestedDIDDocumentMetadata,
    ) -> Result<(did_webplus::DIDDocument, did_webplus::DIDDocumentMetadata)> {
        let (did_document_string, did_document_metadata) = self
            .resolve_did_document_string(did_query, requested_did_document_metadata)
            .await?;
        let did_document: did_webplus::DIDDocument = serde_json::from_str(&did_document_string)
            .map_err(|e| Error::MalformedDIDDocument(e.to_string().into()))?;
        Ok((did_document, did_document_metadata))
    }
}
