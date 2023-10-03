use std::borrow::Cow;

use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, RequestedDIDDocumentMetadata, DID};

/// Trait defining the DID Resolver data model.  The two mock implementations of this are
/// MockResolverFull (keeps a local MockVerifiedCache of all DIDs it has resolved) and
/// MockResolverLite (does not keep a local MockVerifiedCache, and instead outsources the
/// retrieval and verification of DID microledgers to a MockVDG).
pub trait MockResolver {
    /// This resolves the given DID, returning the DID document and its metadata.  Only
    /// the metadata requested in the RequestedDIDDocumentMetadata struct will be returned.
    /// Requesting less metadata will result in a faster resolution, as some operations
    /// may be able to occur fully offline.  In particular, if you don't request `currency`,
    /// then there's no need to contact the DID's VDR to determine the DID's current version.
    fn resolve<'s>(
        &'s mut self,
        did: &DID,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error>;
}
