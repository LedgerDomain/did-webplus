use crate::{DIDDocument, DIDDocumentMetadata, Error, DID};

/// Trait defining the DID microledger data model.  The trait is defined generally enough so that
/// it could be implemented for a Microledger held entirely in memory, or one stored in a database.
/// The lifetime parameter for the view trait defines how long the returned references are valid.
/// If the microledger is backed by a database, then the lifetime parameter would be 'static, since
/// the database queries are returning copies of the data, and there isn't a persistent in-memory
/// copy of that data.  Whereas if the microledger is backed by an in-memory data structure, then
/// the lifetime parameter would be the lifetime of that in-memory structure.
// TODO: Need an async version for a sqlx-backed implementation.
pub trait MicroledgerView<'v> {
    /// This is the DID that controls this microledger and that all DID documents in this microledger share.
    fn did(&self) -> &'v DID;
    // /// The microledger height is the number of DID documents in the microledger.
    // fn microledger_height(&self) -> u32;
    /// Returns the root (first) DID document of the microledger.
    fn root_did_document(&self) -> &'v DIDDocument;
    /// Returns the latest DID document in the microledger.
    fn latest_did_document(&self) -> &'v DIDDocument;
    /// Select a range of DID documents based on version_id.  Optionally specify a begin and end (range
    /// is inclusive on both ends) version_id value for the range.  If version_id_begin_o is None, then
    /// it is treated as 0.  If version_id_end_o is None, then it is treated as u32::MAX.  What's
    /// returned is the number of selected DID documents and an iterator over them.
    fn select_did_documents<'s>(
        &'s self,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> (
        u32,
        Box<dyn std::iter::Iterator<Item = &'v DIDDocument> + 'v>,
    );
    /// Returns the node at the given version_id.
    fn did_document_for_version_id(&self, version_id: u32) -> Result<&'v DIDDocument, Error>;
    /// Returns the node whose DID document has the given self-hash.
    fn did_document_for_self_hash(
        &self,
        self_hash: &selfhash::KERIHash,
    ) -> Result<&'v DIDDocument, Error>;
    /// Returns the node that is valid at the given time.
    fn did_document_valid_at_time(
        &self,
        time: time::OffsetDateTime,
    ) -> Result<&'v DIDDocument, Error>;
    /// Returns the DIDDocumentMetadata for the given DIDDocument.  Note that this depends on the
    /// whole state of the DID's Microledger -- in particular, on the first and last DID documents,
    /// as well as the "next" DID document from the specified one.
    fn did_document_metadata_for(&self, did_document: &DIDDocument) -> DIDDocumentMetadata {
        let latest_did_document = self.latest_did_document();
        let did_document_is_latest = did_document.self_hash() == latest_did_document.self_hash();
        let next_did_document_o = if did_document_is_latest {
            None
        } else {
            Some(
                self.did_document_for_version_id(did_document.version_id() + 1)
                    .unwrap(),
            )
        };
        DIDDocumentMetadata::new(
            self.root_did_document().valid_from,
            next_did_document_o.as_ref().map(|x| x.valid_from().clone()),
            next_did_document_o.as_ref().map(|x| x.version_id()),
            latest_did_document.valid_from().clone(),
            latest_did_document.version_id(),
        )
    }
    /// Resolve the DID document and associated DID document metadata with optional query params.  If no
    /// query params are given, then the latest will be returned.  If multiple query params are given,
    /// then they will all be checked for consistency.
    fn resolve(
        &self,
        version_id_o: Option<u32>,
        self_hash_o: Option<&selfhash::KERIHash>,
    ) -> Result<(&'v DIDDocument, DIDDocumentMetadata), Error> {
        let did_document = match (version_id_o, self_hash_o) {
            (Some(version_id), None) => self.did_document_for_version_id(version_id)?,
            (None, Some(self_hash)) => self.did_document_for_self_hash(self_hash)?,
            (None, None) => self.latest_did_document(),
            (Some(version_id), Some(self_hash)) => {
                let did_document = self.did_document_for_version_id(version_id)?;
                if did_document.self_hash() != self_hash {
                    return Err(Error::Invalid("The self-hash of the DID document for given version_id does not match the given self-hash"));
                }
                did_document
            }
        };
        let did_document_metadata = self.did_document_metadata_for(&did_document);
        Ok((did_document, did_document_metadata))
    }
    // /// Perform a full traversal and verification of the entire Microledger.  This is linear in the
    // /// number of nodes in the Microledger, and it isn't intended to be called except in debugging and
    // /// testing.
    // fn verify_full(&self) -> Result<(), Error> {
    //     unimplemented!("blah");
    //     // // TODO: implement a "verification cache" which stores the results of the verification so that
    //     // // repeated calls to this function are not redundant.

    //     // // let microledger_height = 1 + self.non_root_did_document_v.len();
    //     // // if self.self_hash_version_id_m.len() != microledger_height {
    //     // //     return Err(Error::Malformed(
    //     // //         "said_version_id_m length does not match microledger height",
    //     // //     ));
    //     // // }
    //     // // if self.valid_from_version_id_m.len() != microledger_height {
    //     // //     return Err(Error::Malformed(
    //     // //         "valid_from_version_id_m length does not match microledger height",
    //     // //     ));
    //     // // }
    //     // // for version_id in self.self_hash_version_id_m.values() {
    //     // //     if *version_id as usize >= microledger_height {
    //     // //         return Err(Error::Malformed(
    //     // //             "said_version_id_m contains version_id that is >= microledger height",
    //     // //         ));
    //     // //     }
    //     // // }
    //     // // for version_id in self.valid_from_version_id_m.values() {
    //     // //     if *version_id as usize >= microledger_height {
    //     // //         return Err(Error::Malformed(
    //     // //             "valid_from_version_id_m contains version_id that is >= microledger height",
    //     // //         ));
    //     // //     }
    //     // // }

    //     // // TODO: More verification regarding the said_version_id_m and valid_from_version_id_m maps.

    //     // // Verify the root node.
    //     // self.root_did_document().verify_nonrecursive()?;
    //     // let version_id_begin = 1u32;
    //     // let version_id_end = self.latest_did_document().version_id() + 1;
    //     // // Verify each non-root node.
    //     // let mut prev_did_document = DIDDocument::from(self.root_did_document());
    //     // for version_id in version_id_begin..version_id_end {
    //     //     let non_root_did_document = self
    //     //         .did_document_for_version_id(version_id)?
    //     //         .as_non_root_did_document()
    //     //         .expect("programmer error");
    //     //     non_root_did_document.verify_nonrecursive(prev_did_document)?;
    //     //     prev_did_document = DIDDocument::from(non_root_did_document);
    //     // }

    //     // Ok(())
    // }
}
