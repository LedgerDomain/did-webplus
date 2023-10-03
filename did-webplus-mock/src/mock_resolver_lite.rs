use std::{
    borrow::Cow,
    sync::{Arc, RwLock},
};

use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, DID};

use crate::{MockResolver, MockVDG};

// This is a "light" resolver which doesn't keep a MockVerifiedCache, and instead outsources
// the retrieval and verification of DID microledgers to a MockVDG.  In its mock implementation,
// this seems to do almost nothing, just forwards the call to MockVDG.  However, the real "light"
// resolver would be a thin wrapper around making the appropriate HTTP request to the VDG (which
// might include authentication or an API key).
pub struct MockResolverLite {
    /// Analogous to the User-Agent HTTP header, used to identify the agent making requests to the VDR,
    /// for more clarity in logging.
    pub user_agent: String,
    /// Mock connection to the trusted VDG.  Just use one for now.  Potentially there could be backups.
    mock_vdg_la: Arc<RwLock<MockVDG>>,
}

impl MockResolverLite {
    pub fn new(user_agent: String, mock_vdg_la: Arc<RwLock<MockVDG>>) -> Self {
        Self {
            user_agent,
            mock_vdg_la,
        }
    }
}

impl MockResolver for MockResolverLite {
    fn resolve<'s>(
        &'s mut self,
        did: &DID,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error> {
        let mut mock_vdg_g = self.mock_vdg_la.write().unwrap();
        use crate::MockVDS;
        let (did_document, did_document_metadata) =
            mock_vdg_g.resolve(self.user_agent.as_str(), did, version_id_o, self_hash_o)?;
        Ok((Cow::Owned(did_document), did_document_metadata))
    }
}
