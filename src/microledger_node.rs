use crate::{DIDDocument, DIDDocumentMetadata, Error, SAID_HASH_FUNCTION_CODE};

pub struct MicroledgerNode {
    did_document_hash: String,
    did_document: DIDDocument,
    did_document_metadata: DIDDocumentMetadata,
}

impl MicroledgerNode {
    pub fn did_document_hash(&self) -> &str {
        &self.did_document_hash
    }
    pub fn did_document(&self) -> &DIDDocument {
        &self.did_document
    }
    pub fn did_document_metadata(&self) -> &DIDDocumentMetadata {
        &self.did_document_metadata
    }
    pub fn did_document_metadata_mut(&mut self) -> &mut DIDDocumentMetadata {
        &mut self.did_document_metadata
    }
    /// Create a root MicroledgerNode from the given DIDDocument.  This will cause the SAID
    /// of the DIDDocument to be computed and populated where appropriate, thereby sealing
    /// the initial DIDDocument.  In particular, the SAID of this initial DIDDocument
    /// forms part of the DID itself.
    pub fn create_root(mut did_document: DIDDocument) -> Result<Self, Error> {
        use said::sad::SAD;
        did_document.compute_digest();

        did_document.verify_initial()?;
        assert_eq!(
            did_document.version_id, 0,
            "programmer error: this should have been guaranteed by DIDDocument::verify_initial"
        );

        let did_document_hash = did_document.hash(&SAID_HASH_FUNCTION_CODE);
        let did_document_metadata = DIDDocumentMetadata {
            created: did_document.valid_from.clone(),
            valid_until_o: None,
        };

        Ok(Self {
            did_document_hash,
            did_document,
            did_document_metadata,
        })
    }
    /// Note that in order for this to be validly appended to a Microledger, the previous MicroledgerNode's
    /// DIDDocumentMetadata must be updated.  That is handled separately by Microledger after this.
    pub fn create_non_root(
        new_did_document: DIDDocument,
        prev_microledger_node: &Self,
    ) -> Result<Self, Error> {
        if prev_microledger_node
            .did_document_metadata
            .valid_until_o
            .is_some()
        {
            return Err(Error::InvalidDIDWebplusUpdateOperation(
                "branching a did:webplus Microledger is not allowed; prev_microledger_node.did_document_metadata.valid_until_o must be None",
            ));
        }
        new_did_document.verify_non_initial(&prev_microledger_node.did_document)?;

        let did_document_hash = new_did_document.hash(&SAID_HASH_FUNCTION_CODE);
        let did_document_metadata = DIDDocumentMetadata {
            created: new_did_document.valid_from.clone(),
            valid_until_o: None,
        };

        Ok(Self {
            did_document_hash,
            did_document: new_did_document,
            did_document_metadata,
        })
    }
}
