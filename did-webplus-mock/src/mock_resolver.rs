use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, DID};

use crate::{MockVDR, MockVerifiedCache};

pub struct MockResolver {
    /// Analogous to the User-Agent HTTP header, used to identify the agent making requests to the VDR,
    /// in this case, for more clarity in logging.
    pub user_agent: String,
    /// This is our local verified cache of all DIDs we've resolved.
    mock_verified_cache: MockVerifiedCache,
    /// Mock connections to VDRs.
    mock_vdr_lam: HashMap<String, Arc<RwLock<MockVDR>>>,
}

impl MockResolver {
    pub fn new(user_agent: String, mock_vdr_lam: HashMap<String, Arc<RwLock<MockVDR>>>) -> Self {
        let mock_verified_cache_user_agent = format!("{}'s MockVerifiedCache", user_agent);
        Self {
            user_agent,
            mock_verified_cache: MockVerifiedCache::empty(mock_verified_cache_user_agent),
            mock_vdr_lam,
        }
    }
    pub fn resolve<'s>(
        &'s mut self,
        did: &DID,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
    ) -> Result<(&'s DIDDocument, DIDDocumentMetadata), Error> {
        self.mock_verified_cache
            .resolve(did, version_id_o, self_hash_o, &self.mock_vdr_lam)
    }
}
