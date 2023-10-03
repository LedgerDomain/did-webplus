use std::{
    borrow::Cow,
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, RwLock},
};

use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, RequestedDIDDocumentMetadata, DID};

use crate::{MockResolver, MockVDG, MockVDR, MockVerifiedCache};

/// This is a "full" resolver which keeps a MockVerifiedCache of all DIDs it has resolved.
pub struct MockResolverFull {
    /// Analogous to the User-Agent HTTP header, used to identify the agent making requests to the VDR,
    /// for more clarity in logging.
    pub user_agent: String,
    /// This is our local verified cache of all DIDs we've resolved.
    mock_verified_cache: MockVerifiedCache,
    /// Optional mock connection to VDG.  Just use one for now.  Potentially there could be backups.
    /// If this isn't present, then fall through to use of the VDRs.
    mock_vdg_lao: Option<Arc<RwLock<MockVDG>>>,
    /// Mock connections to the VDRs.
    mock_vdr_lam: HashMap<String, Arc<RwLock<MockVDR>>>,
}

impl MockResolverFull {
    pub fn new(
        user_agent: String,
        mock_vdg_lao: Option<Arc<RwLock<MockVDG>>>,
        mock_vdr_lam: HashMap<String, Arc<RwLock<MockVDR>>>,
    ) -> Self {
        let mock_verified_cache =
            MockVerifiedCache::empty(format!("{}'s MockVerifiedCache", user_agent));
        Self {
            user_agent,
            mock_verified_cache,
            mock_vdg_lao,
            mock_vdr_lam,
        }
    }
}

impl MockResolver for MockResolverFull {
    fn resolve<'s>(
        &'s mut self,
        did: &DID,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error> {
        let (did_document, did_document_metadata) =
            if let Some(mock_vdg_la) = self.mock_vdg_lao.as_mut() {
                let mut mock_vdg_g = mock_vdg_la.write().unwrap();
                self.mock_verified_cache.resolve(
                    did,
                    version_id_o,
                    self_hash_o,
                    requested_did_document_metadata,
                    mock_vdg_g.deref_mut(),
                )?
            } else {
                let mut mock_vdr_g = self
                    .mock_vdr_lam
                    .get_mut(did.host())
                    .expect("programmer error: all mock VDRs should have been supplied correctly")
                    .write()
                    .unwrap();
                self.mock_verified_cache.resolve(
                    did,
                    version_id_o,
                    self_hash_o,
                    requested_did_document_metadata,
                    mock_vdr_g.deref_mut(),
                )?
            };
        Ok((Cow::Borrowed(did_document), did_document_metadata))
    }
}
