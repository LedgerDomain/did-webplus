use std::{
    ops::DerefMut,
    sync::{Arc, RwLock},
};

use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, DID};

use crate::{MockVDG, MockVerifiedCache};

// TODO: make a "light" resolver which doesn't keep a MockVerifiedCache, but outsources its work
// to a MockVDG.
pub struct MockResolver {
    /// Analogous to the User-Agent HTTP header, used to identify the agent making requests to the VDR,
    /// for more clarity in logging.
    pub user_agent: String,
    /// This is our local verified cache of all DIDs we've resolved.
    mock_verified_cache: MockVerifiedCache,
    /// Mock connection to VDG.  Just use one for now.  Potentially there could be backups.
    mock_vdg_la: Arc<RwLock<MockVDG>>,
}

impl MockResolver {
    pub fn new(user_agent: String, mock_vdg_la: Arc<RwLock<MockVDG>>) -> Self {
        let mock_verified_cache =
            MockVerifiedCache::empty(format!("{}'s MockVerifiedCache", user_agent));
        Self {
            user_agent,
            mock_verified_cache,
            mock_vdg_la,
        }
    }
    pub fn resolve<'s>(
        &'s mut self,
        did: &DID,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
    ) -> Result<(&'s DIDDocument, DIDDocumentMetadata), Error> {
        let mut mock_vdg_g = self.mock_vdg_la.write().unwrap();
        self.mock_verified_cache
            .resolve(did, version_id_o, self_hash_o, mock_vdg_g.deref_mut())
    }
}
