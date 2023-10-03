use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, RequestedDIDDocumentMetadata, DID};

/// VDS = Verifiable Data Source (this is defined to be the common property that VDR and VDG both have).
/// This represents a service that is capable of servicing DID resolution requests.  The two kinds of
/// VDS are VDR and VDG.
// TODO: These should use &self instead of &mut self
pub trait MockVDS {
    /// Fetch a contiguous sequence of DID documents for the given DID.  Note that the version_id
    /// range is inclusive on both ends; if version_id_begin_o is None, then it is treated as 0,
    /// and if version_id_end_o is None, then it is treated as u32::MAX.  This is what a "full" client
    /// would use to retrieve (and cache) the full DID microledger so that it can do its own local
    /// verification of DID documents and its own local DID resolution.
    // TODO: Potentially the return type could be Result<Vec<Cow<'s, DIDDocument>>, Error>.
    fn fetch_did_documents(
        &mut self,
        requester_user_agent: &str,
        did: &DID,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Result<Vec<DIDDocument>, Error>;
    /// This is what a "light" client would use to do DID resolution.  It's trusting the VerifiableDataSource
    /// to do retrieval and verification of the DID documents on its behalf.  A VDG should be pre-fetching
    /// DID documents from VDRs, so that it can resolve DIDs for these "light" clients in constant time.
    // TODO: Potentially the return type could be Result<Vec<Cow<'s, DIDDocument>>, Error>.
    fn resolve(
        &mut self,
        requester_user_agent: &str,
        did: &DID,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> Result<(DIDDocument, DIDDocumentMetadata), Error>;
}
