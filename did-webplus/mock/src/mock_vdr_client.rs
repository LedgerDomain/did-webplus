use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus_core::Error;

use crate::{MockVDR, VDRClient};

/// Mock (i.e. ephemeral, intra-process) implementation of VDR Client.  Has a map of all the VDRs,
/// indexed by hostname, and uses that to route requests to the appropriate VDR.
pub struct MockVDRClient {
    pub user_agent: String,
    mock_vdr_lam: HashMap<String, Arc<RwLock<MockVDR>>>,
}

impl MockVDRClient {
    pub fn new(user_agent: String, mock_vdr_lam: HashMap<String, Arc<RwLock<MockVDR>>>) -> Self {
        Self {
            user_agent,
            mock_vdr_lam,
        }
    }
}

impl VDRClient for MockVDRClient {
    fn create_did(
        &self,
        root_did_document: did_webplus_core::DIDDocument,
    ) -> Result<did_webplus_core::DID, Error> {
        let hostname = root_did_document.did.hostname();
        let mock_vdr_la = self
            .mock_vdr_lam
            .get(hostname)
            .expect("programmer error: all mock VDRs should have been supplied correctly");
        let mut mock_vdr_g = mock_vdr_la.write().unwrap();
        mock_vdr_g.create_did(self.user_agent.as_str(), root_did_document)
    }
    fn update_did(&self, new_did_document: did_webplus_core::DIDDocument) -> Result<(), Error> {
        let hostname = new_did_document.did.hostname();
        let mock_vdr_la = self
            .mock_vdr_lam
            .get(hostname)
            .expect("programmer error: all mock VDRs should have been supplied correctly");
        let mut mock_vdr_g = mock_vdr_la.write().unwrap();
        mock_vdr_g.update_did(self.user_agent.as_str(), new_did_document)
    }
}
