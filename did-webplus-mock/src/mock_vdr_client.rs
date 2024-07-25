use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use did_webplus::Error;

use crate::{MockVDR, VDRClient};

/// Mock (i.e. ephemeral, intra-process) implementation of VDR Client.  Has a map of all the VDRs,
/// indexed by host, and uses that to route requests to the appropriate VDR.
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
        root_did_document: did_webplus::DIDDocument,
    ) -> Result<did_webplus::DID, Error> {
        let host = root_did_document.parsed_did.host();
        let mock_vdr_la = self
            .mock_vdr_lam
            .get(host)
            .expect("programmer error: all mock VDRs should have been supplied correctly");
        let mut mock_vdr_g = mock_vdr_la.write().unwrap();
        mock_vdr_g.create_did(self.user_agent.as_str(), root_did_document)
    }
    fn update_did(&self, new_did_document: did_webplus::DIDDocument) -> Result<(), Error> {
        let host = new_did_document.parsed_did.host();
        let mock_vdr_la = self
            .mock_vdr_lam
            .get(host)
            .expect("programmer error: all mock VDRs should have been supplied correctly");
        let mut mock_vdr_g = mock_vdr_la.write().unwrap();
        mock_vdr_g.update_did(self.user_agent.as_str(), new_did_document)
    }
}
