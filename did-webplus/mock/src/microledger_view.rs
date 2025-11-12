use std::ops::Deref;

use did_webplus_core::{RootLevelUpdateRules, UpdatesDisallowed};

/// Trait defining the read-only portion of the DID microledger data model.  The trait is defined
/// generally enough so that it could be implemented for a Microledger held entirely in memory, or
/// one stored in a database.  The lifetime parameter for the view trait defines how long the returned
/// references are valid.  If the microledger is backed by a database, then the lifetime parameter
/// would be 'static, since the database queries are returning copies of the data, and there isn't
/// a persistent in-memory copy of that data.  Whereas if the microledger is backed by an in-memory
/// data structure, then the lifetime parameter would be the lifetime of that in-memory structure.
// TODO: Should &'v DIDDocument be Cow<'v, DIDDocument>?
// TODO: Move this into did-webplus-mock, since it's not used anywhere but there.
pub trait MicroledgerView<'v> {
    /// This is the DID that controls this microledger and that all DID documents in this microledger share.
    fn did(&self) -> &'v did_webplus_core::DID;
    // /// The microledger height is the number of DID documents in the microledger.
    // fn microledger_height(&self) -> u32;
    /// Returns the root (first) DID document of the microledger.
    fn root_did_document(&self) -> &'v did_webplus_core::DIDDocument;
    /// Returns the latest DID document in the microledger.
    fn latest_did_document(&self) -> &'v did_webplus_core::DIDDocument;
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
        Box<dyn std::iter::Iterator<Item = &'v did_webplus_core::DIDDocument> + 'v>,
    );
    /// Returns the node at the given version_id.
    fn did_document_for_version_id(
        &self,
        version_id: u32,
    ) -> did_webplus_core::Result<&'v did_webplus_core::DIDDocument>;
    /// Returns the node whose DID document has the given self-hash.
    fn did_document_for_self_hash(
        &self,
        self_hash: &mbx::MBHashStr,
    ) -> did_webplus_core::Result<&'v did_webplus_core::DIDDocument>;
    /// Returns the node that is valid at the given time.
    fn did_document_valid_at_time(
        &self,
        time: time::OffsetDateTime,
    ) -> did_webplus_core::Result<&'v did_webplus_core::DIDDocument>;
    /// Returns the DIDDocumentMetadata for the given DIDDocument.  Note that this depends on the
    /// whole state of the DID's Microledger -- in particular, on the first and last DID documents,
    /// as well as the "next" DID document from the specified one.  Note that the correctness of
    /// the metadata depends on this Microledger being up-to-date enough to service the requested
    /// metadata.
    ///
    /// For example, if requested_did_document_metadata.currency is true, then the Microledger must be
    /// completely up-to-date relative to the DID's VDR.  Whereas, if requested_did_document_metadata.idempotent
    /// is true, and requested_did_document_metadata.currency is false, then the Microledger only needs
    /// to be up-to-date through the next DID document relative to the one being resolved.
    fn did_document_metadata_for(
        &self,
        did_document: &did_webplus_core::DIDDocument,
        _did_resolution_options: did_webplus_core::DIDResolutionOptions,
    ) -> did_webplus_core::DIDDocumentMetadata {
        let creation_metadata =
            did_webplus_core::CreationMetadata::new(self.root_did_document().valid_from);

        let next_update_metadata_o = if let Ok(next_did_document) =
            self.did_document_for_version_id(did_document.version_id + 1)
        {
            Some(did_webplus_core::NextUpdateMetadata::new(
                next_did_document.valid_from,
                next_did_document.version_id,
            ))
        } else {
            None
        };

        let latest_update_metadata = did_webplus_core::LatestUpdateMetadata::new(
            self.latest_did_document().valid_from,
            self.latest_did_document().version_id,
        );

        let deactivated = self.latest_did_document().update_rules
            == RootLevelUpdateRules::UpdatesDisallowed(UpdatesDisallowed {});

        did_webplus_core::DIDDocumentMetadata {
            creation_metadata_o: Some(creation_metadata),
            next_update_metadata_o,
            latest_update_metadata_o: Some(latest_update_metadata),
            deactivated_o: Some(deactivated),
        }
    }
    /// Resolve the DID document and associated DID document metadata with optional query params.  If no
    /// query params are given, then the latest will be returned.  If multiple query params are given,
    /// then they will all be checked for consistency.  Note that the correctness of the metadata depends
    /// on this Microledger being up-to-date enough to service the requested metadata.
    ///
    /// For example, if requested_did_document_metadata.currency is true, then the Microledger must be
    /// completely up-to-date relative to the DID's VDR.  Whereas, if requested_did_document_metadata.idempotent
    /// is true, and requested_did_document_metadata.currency is false, then the Microledger only needs
    /// to be up-to-date through the next DID document relative to the one being resolved.
    fn resolve(
        &self,
        version_id_o: Option<u32>,
        self_hash_o: Option<&mbx::MBHashStr>,
        did_resolution_options: did_webplus_core::DIDResolutionOptions,
    ) -> did_webplus_core::Result<(
        &'v did_webplus_core::DIDDocument,
        did_webplus_core::DIDDocumentMetadata,
    )> {
        let did_document = match (version_id_o, self_hash_o) {
            (Some(version_id), None) => self.did_document_for_version_id(version_id)?,
            (None, Some(self_hash)) => self.did_document_for_self_hash(self_hash)?,
            (None, None) => self.latest_did_document(),
            (Some(version_id), Some(self_hash)) => {
                let did_document = self.did_document_for_version_id(version_id)?;
                if did_document.self_hash.deref() != self_hash {
                    return Err(did_webplus_core::Error::Invalid("The self-hash of the DID document for given version_id does not match the given self-hash".into()));
                }
                did_document
            }
        };
        let did_document_metadata =
            self.did_document_metadata_for(&did_document, did_resolution_options);
        Ok((did_document, did_document_metadata))
    }
}
