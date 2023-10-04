use std::{
    borrow::Cow,
    sync::{Arc, RwLock},
};

use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, RequestedDIDDocumentMetadata, DID};

use crate::{MockVDG, Resolver, VDS};

// This is a "thin" resolver which doesn't keep a MockVerifiedCache, and instead outsources
// the retrieval and verification of DID microledgers to a MockVDG.  In its mock implementation,
// this seems to do almost nothing, just forwards the call to MockVDG.  However, the real "thin"
// resolver would be a thin wrapper around making the appropriate HTTP request to the VDG (which
// might include authentication or an API key).
pub struct MockResolverThin {
    /// Analogous to the User-Agent HTTP header, used to identify the agent making requests to the VDR,
    /// for more clarity in logging.
    pub user_agent: String,
    /// Mock connection to the trusted VDG.  Just use one for now.  Potentially there could be backups.
    // TODO: This should be Option<Arc<dyn Resolver>>.
    mock_vdg_la: Arc<RwLock<MockVDG>>,
}

impl MockResolverThin {
    pub fn new(user_agent: String, mock_vdg_la: Arc<RwLock<MockVDG>>) -> Self {
        Self {
            user_agent,
            mock_vdg_la,
        }
    }
}

impl Resolver for MockResolverThin {
    fn get_did_documents<'s>(
        &'s mut self,
        did: &DID,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Result<Box<dyn std::iter::Iterator<Item = Cow<'s, DIDDocument>> + 's>, Error> {
        let mut mock_vdg_g = self.mock_vdg_la.write().unwrap();
        // We have to collect this into a Vec in order to free up the lock on mock_vdg_g.
        let did_document_iv = mock_vdg_g
            .get_did_documents(
                self.user_agent.as_str(),
                did,
                version_id_begin_o,
                version_id_end_o,
            )?
            // .into_iter()
            .map(|did_document_c| Cow::Owned(did_document_c.into_owned()))
            .collect::<Vec<_>>();
        Ok(Box::new(did_document_iv.into_iter()))
    }
    fn resolve_did_document<'s>(
        &'s mut self,
        did: &DID,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error> {
        let mut mock_vdg_g = self.mock_vdg_la.write().unwrap();
        let (did_document_c, did_document_metadata) = mock_vdg_g.resolve_did_document(
            self.user_agent.as_str(),
            did,
            version_id_o,
            self_hash_o,
            requested_did_document_metadata,
        )?;
        Ok((
            Cow::Owned(did_document_c.into_owned()),
            did_document_metadata,
        ))
    }
}
