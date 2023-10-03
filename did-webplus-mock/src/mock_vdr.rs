use did_webplus::{DIDDocument, Error, DID};

use crate::Microledger;

// Mock VDR -- Purely in-memory, intra-process VDR.  Hosts DID microledgers on behalf of DID controllers.
#[derive(Debug)]
pub struct MockVDR {
    pub host: String,
    microledger_m: std::collections::HashMap<DID, Microledger>,
    simulated_latency_o: Option<std::time::Duration>,
}

impl MockVDR {
    pub fn new_with_host(host: String, simulated_latency_o: Option<std::time::Duration>) -> Self {
        Self {
            host,
            microledger_m: std::collections::HashMap::new(),
            simulated_latency_o,
        }
    }
    pub fn create(
        &mut self,
        user_agent: &str,
        root_did_document: DIDDocument,
    ) -> Result<DID, Error> {
        println!(
            "VDR (host: {:?}) servicing CREATE request from {:?} for\n    DID: {}",
            self.host, user_agent, root_did_document.id
        );
        if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
            std::thread::sleep(*simulated_latency);
        }

        if root_did_document.id.host != self.host {
            return Err(Error::Malformed("DID host doesn't match that of VDR"));
        }
        // This construction will fail if the root_did_document isn't valid.
        let microledger = Microledger::create(root_did_document)?;
        use did_webplus::MicroledgerViewTrait;
        if self.microledger_m.contains_key(&microledger.view().did()) {
            return Err(Error::AlreadyExists("DID already exists"));
        }
        let did = microledger.view().did().clone();
        self.microledger_m.insert(did.clone(), microledger);
        Ok(did)
    }
    pub fn update(
        &mut self,
        user_agent: &str,
        non_root_did_document: DIDDocument,
    ) -> Result<(), Error> {
        println!(
            "VDR (host: {:?}) servicing UPDATE request from {:?} for\n    DID: {}",
            self.host, user_agent, non_root_did_document.id
        );
        if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
            std::thread::sleep(*simulated_latency);
        }

        if non_root_did_document.id.host != self.host {
            return Err(Error::Malformed("DID host doesn't match that of VDR"));
        }
        let microledger = self
            .microledger_m
            .get_mut(&non_root_did_document.id)
            .ok_or_else(|| Error::NotFound("DID not found"))?;
        use did_webplus::MicroledgerMutViewTrait;
        microledger.mut_view().update(non_root_did_document)?;
        Ok(())
    }
    pub fn select_did_documents<'s>(
        &'s self,
        user_agent: &str,
        did: &DID,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> Result<Box<dyn std::iter::Iterator<Item = &'s DIDDocument> + 's>, Error> {
        println!(
            "VDR (host: {:?}) servicing SELECT request from {:?} for\n    DID: {}\n    version_id_begin_o: {:?}\n    version_id_end_o: {:?}",
            self.host, user_agent, did, version_id_begin_o, version_id_end_o
        );
        if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
            std::thread::sleep(*simulated_latency);
        }

        let microledger = self.microledger(did)?;
        use did_webplus::MicroledgerViewTrait;
        let did_document_ib = microledger
            .view()
            .select_did_documents(version_id_begin_o, version_id_end_o);
        Ok(did_document_ib)
    }
    // // You could call resolve directly on a VDR if you trust that VDR.  But if you don't, then you
    // // should use a local cache to retrieve and verify the DID's microledger, and potentially reduce
    // // the number of times you need to hit the VDR.
    // pub fn resolve<'a>(
    //     &self,
    //     did: &DID,
    //     version_id_o: Option<u32>,
    //     self_signature_o: Option<&selfsign::KERISignature<'a>>,
    // ) -> Result<(DIDDocument, DIDDocumentMetadata), Error> {
    //     if let Some(simulated_latency) = self.simulated_latency_o.as_ref() {
    //         std::thread::sleep(*simulated_latency);
    //     }

    //     let microledger = self.microledger(did)?;
    //     let (did_document, did_document_metadata) =
    //         microledger.resolve(version_id_o, self_signature_o)?;
    //     Ok((did_document, did_document_metadata))
    // }
    fn microledger<'s>(&'s self, did: &DID) -> Result<&'s Microledger, Error> {
        self.microledger_m
            .get(did)
            .ok_or_else(|| Error::NotFound("DID not found"))
    }
}
