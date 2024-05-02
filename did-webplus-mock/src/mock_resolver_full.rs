use std::{
    borrow::Cow,
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, RwLock},
};

use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, RequestedDIDDocumentMetadata, DID};

use crate::{
    mock_resolver_internal::MockResolverInternal, MockVDG, MockVDR, MockVerifiedCache, Resolver,
};

/// This is a "full" resolver which keeps a MockVerifiedCache of all DIDs it has resolved.
pub struct MockResolverFull {
    /// Analogous to the User-Agent HTTP header, used to identify the agent making requests to the VDR,
    /// for more clarity in logging.
    pub user_agent: String,
    /// This is our local verified cache of all DIDs we've resolved.
    mock_verified_cache: MockVerifiedCache,
    /// Optional mock connection to VDG.  Just use one for now.  Potentially there could be backups.
    /// If this isn't present, then fall through to use of the VDRs.
    // TODO: This should be Option<Arc<dyn Resolver>>.
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

impl Resolver for MockResolverFull {
    fn get_did_documents<'s>(
        &'s mut self,
        did: &DID,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Result<Box<dyn std::iter::Iterator<Item = Cow<'s, DIDDocument>> + 's>, Error> {
        if let Some(mock_vdg_la) = self.mock_vdg_lao.as_ref() {
            let mut mock_vdg_g = mock_vdg_la.write().unwrap();
            self.mock_verified_cache.get_did_documents(
                self.user_agent.as_str(),
                did,
                version_id_begin_o,
                version_id_end_o,
                &mut MockResolverInternal {
                    user_agent: self.user_agent.as_str(),
                    vds: mock_vdg_g.deref_mut(),
                },
            )
        } else {
            let mut mock_vdr_g = self
                .mock_vdr_lam
                .get_mut(did.host())
                .expect("programmer error: all mock VDRs should have been supplied correctly")
                .write()
                .unwrap();
            self.mock_verified_cache.get_did_documents(
                self.user_agent.as_str(),
                did,
                version_id_begin_o,
                version_id_end_o,
                &mut MockResolverInternal {
                    user_agent: self.user_agent.as_str(),
                    vds: mock_vdr_g.deref_mut(),
                },
            )
        }
    }
    fn resolve_did_document<'s>(
        &'s mut self,
        did: &DID,
        self_hash_o: Option<&selfhash::KERIHash>,
        version_id_o: Option<u32>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error> {
        if let Some(mock_vdg_la) = self.mock_vdg_lao.as_ref() {
            let mut mock_vdg_g = mock_vdg_la.write().unwrap();
            self.mock_verified_cache.resolve_did_document(
                did,
                version_id_o,
                self_hash_o,
                requested_did_document_metadata,
                &mut MockResolverInternal {
                    user_agent: self.user_agent.as_str(),
                    vds: mock_vdg_g.deref_mut(),
                },
            )
        } else {
            let mut mock_vdr_g = self
                .mock_vdr_lam
                .get_mut(did.host())
                .expect("programmer error: all mock VDRs should have been supplied correctly")
                .write()
                .unwrap();
            self.mock_verified_cache.resolve_did_document(
                did,
                version_id_o,
                self_hash_o,
                requested_did_document_metadata,
                &mut MockResolverInternal {
                    user_agent: self.user_agent.as_str(),
                    vds: mock_vdr_g.deref_mut(),
                },
            )
        }
    }
}
