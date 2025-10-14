use std::borrow::Cow;

use did_webplus_core::{DIDDocument, DIDDocumentMetadata, DIDStr, Error, DID};

use crate::{Microledger, MicroledgerMutView, MicroledgerView, VDS};

// Mock VDR -- Purely in-memory, intra-process VDR.  Hosts DID microledgers on behalf of DID controllers.
#[derive(Debug)]
pub struct MockVDR {
    pub hostname: String,
    pub did_port_o: Option<u16>,
    microledger_m: std::collections::HashMap<DID, Microledger>,
    /// Optional simulated network latency duration.  If present, then all VDR operations will sleep
    /// for this duration before beginning their work.
    simulated_latency_o: Option<std::time::Duration>,
}

impl MockVDR {
    pub fn new_with_hostname(
        hostname: String,
        did_port_o: Option<u16>,
        simulated_latency_o: Option<std::time::Duration>,
    ) -> Self {
        Self {
            hostname,
            did_port_o,
            microledger_m: std::collections::HashMap::new(),
            simulated_latency_o,
        }
    }
    pub fn create_did(
        &mut self,
        user_agent: &str,
        root_did_document: DIDDocument,
    ) -> Result<DID, Error> {
        println!(
            "VDR (hostname: {:?}) servicing CREATE DID request from {:?} for\n    DID: {}",
            self.hostname, user_agent, root_did_document.did
        );
        self.simulate_latency_if_necessary();

        if root_did_document.did.hostname() != self.hostname.as_str() {
            return Err(Error::Malformed("DID hostname doesn't match that of VDR"));
        }
        if root_did_document.did.port_o() != self.did_port_o {
            return Err(Error::Malformed("DID port doesn't match that of VDR"));
        }

        // This construction will fail if the root_did_document isn't valid.
        let microledger = Microledger::create(root_did_document)?;
        if self.microledger_m.contains_key(microledger.view().did()) {
            return Err(Error::AlreadyExists("DID already exists"));
        }
        let did = microledger.view().did().to_owned();
        self.microledger_m.insert(did.clone(), microledger);
        Ok(did)
    }
    pub fn update_did(
        &mut self,
        user_agent: &str,
        new_did_document: DIDDocument,
    ) -> Result<(), Error> {
        println!(
            "VDR (hostname: {:?}, did_port_o: {:?}) servicing UPDATE DID request from {:?} for\n    DID: {}",
            self.hostname, self.did_port_o, user_agent, new_did_document.did
        );
        self.simulate_latency_if_necessary();

        if new_did_document.did.hostname() != self.hostname.as_str() {
            return Err(Error::Malformed("DID hostname doesn't match that of VDR"));
        }
        if new_did_document.did.port_o() != self.did_port_o {
            return Err(Error::Malformed("DID port doesn't match that of VDR"));
        }
        let microledger = self
            .microledger_m
            .get_mut(&new_did_document.did)
            .ok_or_else(|| Error::NotFound("DID not found"))?;
        microledger.mut_view().update(new_did_document)?;
        Ok(())
    }
    fn microledger<'s>(&'s self, did: &DIDStr) -> Result<&'s Microledger, Error> {
        self.microledger_m
            .get(did)
            .ok_or_else(|| Error::NotFound("DID not found"))
    }
    fn simulate_latency_if_necessary(&self) {
        if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
            std::thread::sleep(*simulated_latency);
        }
    }
}

impl VDS for MockVDR {
    fn get_did_documents<'s>(
        &'s mut self,
        requester_user_agent: &str,
        did: &DIDStr,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Result<Box<dyn std::iter::Iterator<Item = Cow<'s, DIDDocument>> + 's>, Error> {
        println!(
            "VDR({:?})::fetch_did_documents\n    requester_user_agent: {:?}\n    DID: {}\n    version_id_begin_o: {:?}\n    version_id_end_o: {:?}",
            self.hostname, requester_user_agent, did, version_id_begin_o, version_id_end_o
        );
        self.simulate_latency_if_necessary();

        let microledger = self.microledger(did)?;
        let (_, did_document_ib) = microledger
            .view()
            .select_did_documents(version_id_begin_o, version_id_end_o);
        let did_document_cib =
            Box::new(did_document_ib.map(|did_document| Cow::Borrowed(did_document)));
        Ok(did_document_cib)
    }
    fn resolve_did_document<'s>(
        &'s mut self,
        requester_user_agent: &str,
        did: &DIDStr,
        version_id_o: Option<u32>,
        self_hash_o: Option<&mbx::MBHashStr>,
        did_resolution_options: did_webplus_core::DIDResolutionOptions,
    ) -> Result<(Cow<'s, DIDDocument>, DIDDocumentMetadata), Error> {
        println!(
            "VDR({:?})::resolve\n    requester_user_agent: {:?}\n    DID: {}\n    version_id_o: {:?}\n    self_hash_o: {:?}",
            self.hostname, requester_user_agent, did, version_id_o, self_hash_o
        );
        self.simulate_latency_if_necessary();

        let microledger = self.microledger(did)?;
        let (did_document, did_document_metadata) =
            microledger
                .view()
                .resolve(version_id_o, self_hash_o, did_resolution_options)?;
        Ok((Cow::Borrowed(did_document), did_document_metadata))
    }
}
