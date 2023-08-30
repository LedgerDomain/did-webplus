use crate::{
    DIDDocumentMetadata, DIDDocumentTrait, Error, NonRootDIDDocument, NonRootDIDDocumentParams,
    RootDIDDocument, RootDIDDocumentParams, MicroledgerNodeTrait,
};

#[derive(Clone, Debug)]
pub struct MicroledgerNode<DIDDocument: DIDDocumentTrait> {
    did_document: DIDDocument,
    did_document_metadata: DIDDocumentMetadata,
}

impl<DIDDocument: DIDDocumentTrait> MicroledgerNode<DIDDocument> {
    /// Returns RootDIDDocument or NonRootDIDDocument, depending on the type parameter.
    pub fn typed_did_document(&self) -> &DIDDocument {
        &self.did_document
    }
}

impl<DIDDocument: DIDDocumentTrait> MicroledgerNodeTrait for MicroledgerNode<DIDDocument> {
    fn did_document(&self) -> Box<&dyn DIDDocumentTrait> {
        Box::new(&self.did_document)
    }
    fn did_document_metadata(&self) -> &DIDDocumentMetadata {
        &self.did_document_metadata
    }
    fn set_did_document_metadata_valid_until(
        &mut self,
        valid_until: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        if self.did_document_metadata.valid_until_o.is_some() {
            return Err(Error::InvalidDIDWebplusUpdateOperation(
                "branching a did:webplus Microledger is not allowed; prev_microledger_node.did_document_metadata.valid_until_o must be None",
            ));
        }
        if valid_until <= self.did_document_metadata.created {
            return Err(Error::InvalidDIDWebplusUpdateOperation(
                "valid_until must be greater than created",
            ));
        }
        self.did_document_metadata.valid_until_o = Some(valid_until);
        Ok(())
    }
}

/// Create a root MicroledgerNode from the given DIDDocument.  This will cause the SAID
/// of the DIDDocument to be computed and populated where appropriate, thereby sealing
/// the initial DIDDocument.  In particular, the SAID of this initial DIDDocument
/// forms part of the DID itself.
pub fn create_root_microledger_node(
    root_did_document_params: RootDIDDocumentParams,
) -> Result<MicroledgerNode<RootDIDDocument>, Error> {
    // Form the root DID document.
    let mut root_did_document = RootDIDDocument {
        id: root_did_document_params.did_webplus_with_placeholder,
        said_o: None,
        version_id: 0,
        valid_from: root_did_document_params.valid_from,
        key_material: root_did_document_params.key_material,
    };
    // Compute the SAID of the root DID document.
    use said::sad::SAD;
    root_did_document.compute_digest();
    // Verify just for good measure.
    root_did_document
        .verify_root()
        .expect("programmer error: DID document should be valid by construction");

    let did_document_metadata = DIDDocumentMetadata {
        created: root_did_document.valid_from.clone(),
        valid_until_o: None,
    };

    Ok(MicroledgerNode {
        did_document: root_did_document,
        did_document_metadata,
    })
}

/// Note that in order for this to be validly appended to a Microledger, the previous MicroledgerNode's
/// DIDDocumentMetadata must be updated.  That is handled separately by Microledger after this.
pub fn create_non_root_microledger_node(
    // new_did_document: DIDDocument,
    non_root_did_document_params: NonRootDIDDocumentParams,
    prev_did_document_b: Box<&dyn DIDDocumentTrait>,
    prev_did_document_metadata: &DIDDocumentMetadata,
) -> Result<MicroledgerNode<NonRootDIDDocument>, Error> {
    if prev_did_document_metadata.valid_until_o.is_some() {
        return Err(Error::InvalidDIDWebplusUpdateOperation(
            "branching a did:webplus Microledger is not allowed; prev_document_metadata.valid_until_o must be None",
        ));
    }

    // Form the new DID document
    let mut new_did_document = NonRootDIDDocument {
        id: prev_did_document_b.id().clone(),
        said_o: None,
        prev_did_document_said: prev_did_document_b.said().clone(),
        version_id: prev_did_document_b.version_id() + 1,
        valid_from: non_root_did_document_params.valid_from,
        key_material: non_root_did_document_params.key_material,
    };
    // Compute and populate its SAID.
    use said::sad::SAD;
    new_did_document.compute_digest();
    // Verify it against the previous DID document.
    new_did_document
        .verify_non_root(prev_did_document_b)
        .expect("programmer error: DID document should be valid by construction");

    // let did_document_hash = new_did_document.hash(&SAID_HASH_FUNCTION_CODE);
    let did_document_metadata = DIDDocumentMetadata {
        created: new_did_document.valid_from.clone(),
        valid_until_o: None,
    };

    Ok(MicroledgerNode {
        did_document: new_did_document,
        did_document_metadata,
    })
}
