use std::{
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, RwLock},
};

use crate::{MockVDR, MockVDS, MockVerifiedCache};
use did_webplus::{DIDDocument, DIDDocumentMetadata, Error, RequestedDIDDocumentMetadata, DID};

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

impl MockVDS for MockVDG {
    fn fetch_did_documents(
        &mut self,
        requester_user_agent: &str,
        did: &DID,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Result<Vec<DIDDocument>, Error> {
        println!("MockVDG({:?})::fetch_did_documents;\n    requester_user_agent: {}\n    DID: {}\n    version_id_begin_o: {:?}\n    version_id_end_o: {:?}", self.user_agent, requester_user_agent, did, version_id_begin_o, version_id_end_o);

        self.simulate_latency_if_necessary();

        // Determine if the VDG already has the requested DID documents in its cache.
        // If so, then the request can be immediately serviced.  Otherwise, the VDR will
        // have to be hit to retrieve the DID documents.

        // The first condition is that if version_id_end_o is Some(_), then there is a finite
        // range of DID documents being requested, which we might already have in the cache.
        // Otherwise, version_id_end_o is None, which means we're forced to hit the VDR.
        let version_id_begin = version_id_begin_o.unwrap_or(0);
        if let Some(version_id_end) = version_id_end_o {
            let requested_did_document_count = version_id_end - version_id_begin;

            use did_webplus::MicroledgerView;
            // The second condition is if the VDG has any of the DID's DID documents in its cache,
            // then it can check for the specifically requested version_id-s.
            if let Some(microledger_view) = self.mock_verified_cache.microledger_view(did) {
                let (did_document_count, did_document_ib) =
                    microledger_view.select_did_documents(version_id_begin_o, version_id_end_o);
                assert!(did_document_count <= requested_did_document_count);
                if did_document_count == requested_did_document_count {
                    // We already have all the requested DID documents here in the cache, so return them.
                    // Convert the iterator of references into a Vec of owned DIDDocument-s.
                    let did_document_v = did_document_ib.cloned().collect();
                    return Ok(did_document_v);
                }
            }
        }

        // If we got here, it means that we have to hit the VDR before returning the DID documents.
        {
            let mut mock_vdr_g = self
                .mock_vdr_lam
                .get(did.host())
                .expect("programmer error: all mock VDRs should have been supplied correctly")
                .write()
                .unwrap();
            self.mock_verified_cache
                .update_cache(did, mock_vdr_g.deref_mut())?;
        }

        // Now we can simply return the requested DID documents from the cache.
        {
            use did_webplus::MicroledgerView;
            let (_, did_document_ib) = self
                .mock_verified_cache
                .microledger_view(did)
                .expect("programmer error: if we got this far, the DID should be in the cache")
                .select_did_documents(version_id_begin_o, version_id_end_o);
            // Convert the iterator of references into a Vec of owned DIDDocument-s.
            let did_document_v = did_document_ib.cloned().collect();
            Ok(did_document_v)
        }
    }
    fn resolve(
        &mut self,
        requester_user_agent: &str,
        did: &DID,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> Result<(DIDDocument, DIDDocumentMetadata), Error> {
        println!(
            "MockVDG({:?})::resolve;\n    requester_user_agent: {:?}\n    DID: {}\n    version_id_o: {:?}\n    self_hash_o: {:?}",
            self.user_agent, requester_user_agent, did, version_id_o, self_hash_o
        );
        self.simulate_latency_if_necessary();

        // TODO: Use the requested_did_document_metadata properly

        // TODO: Resolve totally locally if possible.
        // TODO: Need to handle the different kinds of DID document metadata.
        // if let Ok((did_document, did_document_metadata)) =
        //     self.microledger.resolve(version_id_o, self_hash_o)
        // {
        //     // If the resolved, cached DID document is not the latest DID document in the local cache,
        //     // then it can't be the latest in the VDR (which is the authority on latest-ness), so there's
        //     // no reason to hit the VDR.
        //     if did_document_metadata.next_version_id_o.is_some() {
        //         return Ok((did_document, did_document_metadata));
        //     }
        //     // Otherwise, we have the DID document, but we don't know that it's the latest, so we'll
        //     // need to hit the VDR to check if there are any previously-uncached DID documents.
        //     let new_did_document_count = self.update_cache(mock_vdr_la.read().unwrap().deref())?;
        //     if new_did_document_count == 0 {
        //         // If the update_cache call returned 0, then the local cache was already up to date,
        //         // so we can just return.
        //         return Ok((did_document, did_document_metadata));
        //     } else {
        //         // Otherwise, we need to re-resolve using the recent updates.
        //         return self.microledger.resolve(version_id_o, self_hash_o);
        //     }
        // }

        // Retrieve the mock connection to the VDR for this DID.
        let mut mock_vdr_g = self
            .mock_vdr_lam
            .get(did.host())
            .expect("pass")
            .write()
            .unwrap();
        // Ensure the cache is up-to-date.
        self.mock_verified_cache
            .update_cache(did, mock_vdr_g.deref_mut())?;
        // Resolve the DID document from the cache.
        use did_webplus::MicroledgerView;
        let (did_document, did_document_metadata) = self
            .mock_verified_cache
            .microledger_view(did)
            .expect("programmer error")
            .resolve(version_id_o, self_hash_o, requested_did_document_metadata)?;
        Ok((did_document.clone(), did_document_metadata))
    }
}
