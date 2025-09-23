use crate::{
    DIDDocument, DIDDocumentMetadata, DIDDocumentMetadataConstant, DIDDocumentMetadataCurrency,
    DIDDocumentMetadataIdempotent, DIDStr, Error, MicroledgerView, RequestedDIDDocumentMetadata,
};
use std::ops::Deref;

/// Async version of the MicroledgerView trait, which defines the read-only portion of the DID
/// microledger data model.  The trait is defined generally enough so that it could be implemented
/// for a Microledger held entirely in memory, or one stored in a database.  The lifetime parameter
/// for the view trait defines how long the returned references are valid.  If the microledger is
/// backed by a database, then the lifetime parameter would be 'static, since the database queries
/// are returning copies of the data, and there isn't a persistent in-memory copy of that data.
/// Whereas if the microledger is backed by an in-memory data structure, then the lifetime parameter
/// would be the lifetime of that in-memory structure.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait MicroledgerViewAsync<'v> {
    /// This is the DID that controls this microledger and that all DID documents in this microledger share.
    async fn did(&self) -> &'v DIDStr;
    // /// The microledger height is the number of DID documents in the microledger.
    // async fn microledger_height(&self) -> u32;
    /// Returns the root (first) DID document of the microledger.
    async fn root_did_document(&self) -> &'v DIDDocument;
    /// Returns the latest DID document in the microledger.
    async fn latest_did_document(&self) -> &'v DIDDocument;
    /// Select a range of DID documents based on version_id.  Optionally specify a begin and end (range
    /// is inclusive on both ends) version_id value for the range.  If version_id_begin_o is None, then
    /// it is treated as 0.  If version_id_end_o is None, then it is treated as u32::MAX.  What's
    /// returned is the number of selected DID documents and an iterator over them.
    async fn select_did_documents<'s>(
        &'s self,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> (
        u32,
        Box<dyn std::iter::Iterator<Item = &'v DIDDocument> + 'v>,
    );
    /// Returns the node at the given version_id.
    async fn did_document_for_version_id(&self, version_id: u32) -> Result<&'v DIDDocument, Error>;
    /// Returns the node whose DID document has the given self-hash.
    async fn did_document_for_self_hash(
        &self,
        self_hash: &mbx::MBHashStr,
    ) -> Result<&'v DIDDocument, Error>;
    /// Returns the node that is valid at the given time.
    async fn did_document_valid_at_time(
        &self,
        time: time::OffsetDateTime,
    ) -> Result<&'v DIDDocument, Error>;
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
    async fn did_document_metadata_for(
        &self,
        did_document: &DIDDocument,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> DIDDocumentMetadata {
        let constant_o = if requested_did_document_metadata.constant {
            Some(DIDDocumentMetadataConstant {
                created: self.root_did_document().await.valid_from,
            })
        } else {
            None
        };
        let idempotent_o = if requested_did_document_metadata.idempotent {
            let next_did_document_o = if let Ok(next_did_document) = self
                .did_document_for_version_id(did_document.version_id + 1)
                .await
            {
                Some(next_did_document)
            } else {
                None
            };
            let next_update_o =
                next_did_document_o.map(|next_did_document| next_did_document.valid_from);
            let next_version_id_o =
                next_did_document_o.map(|next_did_document| next_did_document.version_id);
            Some(DIDDocumentMetadataIdempotent {
                next_update_o,
                next_version_id_o,
            })
        } else {
            None
        };
        let currency_o = if requested_did_document_metadata.currency {
            let latest_did_document = self.latest_did_document().await;
            Some(DIDDocumentMetadataCurrency {
                most_recent_update: latest_did_document.valid_from,
                most_recent_version_id: latest_did_document.version_id,
            })
        } else {
            None
        };

        DIDDocumentMetadata {
            constant_o,
            idempotent_o,
            currency_o,
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
    async fn resolve(
        &self,
        version_id_o: Option<u32>,
        self_hash_o: Option<&mbx::MBHashStr>,
        requested_did_document_metadata: RequestedDIDDocumentMetadata,
    ) -> Result<(&'v DIDDocument, DIDDocumentMetadata), Error> {
        let did_document = match (version_id_o, self_hash_o) {
            (Some(version_id), None) => self.did_document_for_version_id(version_id).await?,
            (None, Some(self_hash)) => self.did_document_for_self_hash(self_hash).await?,
            (None, None) => self.latest_did_document().await,
            (Some(version_id), Some(self_hash)) => {
                let did_document = self.did_document_for_version_id(version_id).await?;
                if did_document.self_hash.deref() != self_hash {
                    return Err(Error::Invalid("The self-hash of the DID document for given version_id does not match the given self-hash"));
                }
                did_document
            }
        };
        let did_document_metadata = self
            .did_document_metadata_for(&did_document, requested_did_document_metadata)
            .await;
        Ok((did_document, did_document_metadata))
    }
}

/// Default implementation for MicroledgerViewAsync for any type that implements MicroledgerView
/// and Sync.  Thus it's preferred to implement the sync version of the trait if at all possible,
/// and then the async version will be automatically derived.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<'v, V: MicroledgerView<'v> + Sync> MicroledgerViewAsync<'v> for V {
    async fn did(&self) -> &'v DIDStr {
        MicroledgerView::did(self)
    }
    async fn root_did_document(&self) -> &'v DIDDocument {
        MicroledgerView::root_did_document(self)
    }
    async fn latest_did_document(&self) -> &'v DIDDocument {
        MicroledgerView::latest_did_document(self)
    }
    async fn select_did_documents<'s>(
        &'s self,
        version_id_begin_o: Option<u32>,
        version_id_end_o: Option<u32>,
    ) -> (
        u32,
        Box<dyn std::iter::Iterator<Item = &'v DIDDocument> + 'v>,
    ) {
        MicroledgerView::select_did_documents(self, version_id_begin_o, version_id_end_o)
    }
    async fn did_document_for_version_id(&self, version_id: u32) -> Result<&'v DIDDocument, Error> {
        MicroledgerView::did_document_for_version_id(self, version_id)
    }
    async fn did_document_for_self_hash(
        &self,
        self_hash: &mbx::MBHashStr,
    ) -> Result<&'v DIDDocument, Error> {
        MicroledgerView::did_document_for_self_hash(self, self_hash)
    }
    async fn did_document_valid_at_time(
        &self,
        time: time::OffsetDateTime,
    ) -> Result<&'v DIDDocument, Error> {
        MicroledgerView::did_document_valid_at_time(self, time)
    }
}
