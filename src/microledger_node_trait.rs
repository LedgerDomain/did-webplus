use crate::{DIDDocumentMetadata, DIDDocumentTrait, Error};

pub trait MicroledgerNodeTrait {
    fn did_document(&self) -> Box<&dyn DIDDocumentTrait>;
    fn did_document_metadata(&self) -> &DIDDocumentMetadata;
    fn set_did_document_metadata_valid_until(
        &mut self,
        valid_until: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error>;
    /// This assumes that the specified prev MicroledgerNode (if any) has already been verified, so
    /// that this call doesn't recurse fully, and only performs one level of verification for the
    /// DID's microledger.
    fn verify(
        &self,
        prev_microledger_node_bo: Option<Box<&dyn MicroledgerNodeTrait>>,
    ) -> Result<(), Error> {
        let did_document = self.did_document();
        // TODO: Validate DID document - metadata relationships.
        // let did_document_metadata = self.did_document_metadata();

        if let Some(prev_microledger_node_b) = prev_microledger_node_bo {
            let prev_did_document_b = prev_microledger_node_b.did_document();
            did_document.verify_non_root(prev_did_document_b)?;
            // TODO: Validate metadata
            // if prev_microledger_node_b.did_document_metadata().valid_until_o.is_none() {
            //     return Err(Error::InvalidDIDMicroledger(
            //         "prev_microledger_node.did_document_metadata.valid_until_o must not be None",
            //     ))
            // }
            // let prev_valid_until = prev_microledger_node_b.did_document_metadata().valid_until_o.unwrap();
        } else {
            self.did_document().verify_root()?;
            // TODO: Validate metadata
        }
        Ok(())
    }
    /// Convenience method for calling self.verify(None).
    fn verify_root(&self) -> Result<(), Error> {
        self.verify(None)
    }
    /// Convenience method for calling self.verify(Some(prev_microledger_node_b)).
    fn verify_non_root(
        &self,
        prev_microledger_node_b: Box<&dyn MicroledgerNodeTrait>,
    ) -> Result<(), Error> {
        self.verify(Some(prev_microledger_node_b))
    }
}
