use crate::{Resolver, VDS};
use did_webplus_core::{DIDDocument, DIDDocumentMetadata, DIDStr, Error, RequestedDIDDocumentMetadata};
use std::borrow::Cow;

/// For use in the implementation of MockResolverFull and MockVDG (both things have a MockVerifiedCache).
pub struct MockResolverInternal<'r> {
    pub user_agent: &'r str,
    pub vds: &'r mut dyn VDS,
}

impl<'r> Resolver for MockResolverInternal<'r> {
    fn get_did_documents<'s>(
        &'s mut self,
        did: &DIDStr,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Result<Box<dyn std::iter::Iterator<Item = Cow<'s, DIDDocument>> + 's>, Error> {
        self.vds
            .get_did_documents(self.user_agent, did, version_id_begin_o, version_id_end_o)
    }
    fn resolve_did_document<'s>(
        &'s mut self,
        did: &DIDStr,
        self_hash_o: Option<&selfhash::KERIHashStr>,
        version_id_o: Option<u32>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error> {
        let (did_document, did_document_metadata) = self.vds.resolve_did_document(
            self.user_agent,
            did,
            version_id_o,
            self_hash_o,
            requested_did_document_metadata,
        )?;
        Ok((did_document, did_document_metadata))
    }
}
