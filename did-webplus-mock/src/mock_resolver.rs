use std::borrow::Cow;

use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, DID};

/// Trait defining the DID Resolver data model.  The two mock implementations of this are
/// MockResolverFull (keeps a local MockVerifiedCache of all DIDs it has resolved) and
/// MockResolverLite (does not keep a local MockVerifiedCache, and instead outsources the
/// retrieval and verification of DID microledgers to a MockVDG).
pub trait MockResolver {
    fn resolve<'s>(
        &'s mut self,
        did: &DID,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error>;
}
