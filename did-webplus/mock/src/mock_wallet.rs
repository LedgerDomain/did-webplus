use std::{collections::HashMap, sync::Arc};

use did_webplus_core::{DIDStr, Error, DID};

use crate::{ControlledDID, VDRClient};

/// Owns private keys and controls set of DIDs, each of which is hosted by a particular VDR.
pub struct MockWallet {
    pub user_agent: String,
    controlled_did_m: HashMap<DID, ControlledDID>,
    vdr_client_a: Arc<dyn VDRClient>,
}

impl std::fmt::Debug for MockWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockWallet")
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl MockWallet {
    pub fn new(user_agent: String, vdr_client_a: Arc<dyn VDRClient>) -> Self {
        Self {
            user_agent,
            controlled_did_m: HashMap::new(),
            vdr_client_a,
        }
    }
    pub fn create_did(
        &mut self,
        did_host: String,
        did_port_o: Option<u16>,
        did_path_o: Option<String>,
    ) -> Result<DID, Error> {
        let controlled_did =
            ControlledDID::create(did_host, did_port_o, did_path_o, self.vdr_client_a.as_ref())?;
        let did = controlled_did.did().to_owned();
        assert!(
            !self.controlled_did_m.contains_key(&did),
            "programmer error: DID already exists -- this is so unlikely that it's almost certainly a bug");
        self.controlled_did_m.insert(did.clone(), controlled_did);
        Ok(did)
    }
    pub fn update_did(&mut self, did: &DIDStr) -> Result<(), Error> {
        let vdr_client_a = self.vdr_client_a.clone();
        let controlled_did = self.controlled_did_mut(did)?;
        controlled_did.update(vdr_client_a.as_ref())
    }
    pub fn controlled_did(&self, did: &DIDStr) -> Result<&ControlledDID, Error> {
        self.controlled_did_m
            .get(did)
            .ok_or(Error::NotFound("DID not found"))
    }
    pub fn controlled_did_mut(&mut self, did: &DIDStr) -> Result<&mut ControlledDID, Error> {
        self.controlled_did_m
            .get_mut(did)
            .ok_or(Error::NotFound("DID not found"))
    }
}
