use crate::{MockResolverInternal, MockVDR, MockVerifiedCache, VDS};
use did_webplus_core::{DIDDocument, DIDDocumentMetadata, DIDStr, Error, RequestedDIDDocumentMetadata};
use std::{
    borrow::Cow,
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, RwLock},
};

/// Mock (i.e. ephemeral, intra-process) implementation of Verifiable Data Gateway.  Handles retrieval,
/// caching, and verification of did:webplus microledgers.
pub struct MockVDG {
    /// Analogous to the User-Agent HTTP header, used to identify the agent making requests to the VDR,
    /// for more clarity in logging.
    user_agent: String,
    /// This is the VDG's local verified cache of all DIDs it has resolved.
    mock_verified_cache: MockVerifiedCache,
    /// Mock connections to VDRs.  The key is the host of the VDR.
    mock_vdr_lam: HashMap<String, Arc<RwLock<MockVDR>>>,
    /// Optional simulated network latency duration.  If present, then all VDG operations will sleep
    /// for this duration before beginning their work.
    simulated_latency_o: Option<std::time::Duration>,
}

impl MockVDG {
    pub fn new(
        user_agent: String,
        mock_vdr_lam: HashMap<String, Arc<RwLock<MockVDR>>>,
        simulated_latency_o: Option<std::time::Duration>,
    ) -> Self {
        let mock_verified_cache =
            MockVerifiedCache::empty(format!("{}'s MockVerifiedCache", user_agent));
        Self {
            user_agent,
            mock_verified_cache,
            mock_vdr_lam,
            simulated_latency_o,
        }
    }
    fn simulate_latency_if_necessary(&self) {
        if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
            std::thread::sleep(*simulated_latency);
        }
    }
}

impl VDS for MockVDG {
    fn get_did_documents<'s>(
        &'s mut self,
        requester_user_agent: &str,
        did: &DIDStr,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Result<Box<dyn std::iter::Iterator<Item = Cow<'s, DIDDocument>> + 's>, Error> {
        println!("MockVDG({:?})::fetch_did_documents;\n    requester_user_agent: {}\n    DID: {}\n    version_id_begin_o: {:?}\n    version_id_end_o: {:?}", self.user_agent, requester_user_agent, did, version_id_begin_o, version_id_end_o);
        self.simulate_latency_if_necessary();

        // This write lock isn't great because the VDR might not actually be hit.
        let mock_vdr_la = self
            .mock_vdr_lam
            .get(did.host())
            .expect("programmer error: all mock VDRs should have been supplied correctly");
        let mut mock_vdr_g = mock_vdr_la.write().unwrap();
        let mut mock_resolver_internal = MockResolverInternal {
            user_agent: self.user_agent.as_str(),
            vds: mock_vdr_g.deref_mut(),
        };
        self.mock_verified_cache.get_did_documents(
            self.user_agent.as_str(),
            did,
            version_id_begin_o,
            version_id_end_o,
            &mut mock_resolver_internal,
        )
    }
    fn resolve_did_document<'s>(
        &'s mut self,
        requester_user_agent: &str,
        did: &DIDStr,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHashStr>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error> {
        println!(
            "MockVDG({:?})::resolve;\n    requester_user_agent: {:?}\n    DID: {}\n    version_id_o: {:?}\n    self_hash_o: {:?}",
            self.user_agent, requester_user_agent, did, version_id_o, self_hash_o
        );
        self.simulate_latency_if_necessary();

        // This write lock isn't great because the VDR might not actually be hit.
        let mock_vdr_la = self
            .mock_vdr_lam
            .get(did.host())
            .expect("programmer error: all mock VDRs should have been supplied correctly");
        let mut mock_vdr_g = mock_vdr_la.write().unwrap();
        let mut mock_resolver_internal = MockResolverInternal {
            user_agent: self.user_agent.as_str(),
            vds: mock_vdr_g.deref_mut(),
        };
        self.mock_verified_cache.resolve_did_document(
            did,
            version_id_o,
            self_hash_o,
            requested_did_document_metadata,
            &mut mock_resolver_internal,
        )
    }
}
