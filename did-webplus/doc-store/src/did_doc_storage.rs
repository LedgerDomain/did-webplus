use crate::{DIDDocRecord, DIDDocRecordFilter, Result};
use did_webplus_core::{DIDDocument, DIDStr};

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait DIDDocStorage: Send + storage_traits::StorageDynT + Sync + 'static {
    /// Attempt to add a DID document to the store.  Will return an error if the DID document already exists.
    /// Note that did_document and did_document_jcs are redundant, and are expected to be consistent, but
    /// did_document_jcs is required because the specific string representation of the DID document is needed
    /// in order for the self-signature and self-hash to be verified.
    async fn add_did_document(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document: &DIDDocument,
        did_document_jcs: &str,
    ) -> Result<()>;
    // TEMP HACK
    async fn add_did_documents(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document_jcs_v: &[&str],
        did_document_v: &[DIDDocument],
    ) -> Result<()>;
    /// Attempt to get a DIDDocRecord with a specific self-hash value from the store.  Will return None if
    /// the requested DIDDocRecord does not exist.
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        self_hash: &mbx::MBHashStr,
    ) -> Result<Option<DIDDocRecord>>;
    /// Attempt to get a DIDDocRecord with a specific version-id value from the store.  Will return None if
    /// the requested DIDDocRecord does not exist.
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>>;
    /// Get the latest DIDDocRecord for the specified DID from the store.  Will return None if the DID has
    /// no DIDDocRecord-s in this store.
    async fn get_latest_did_doc_record(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>>;
    /// Get all DIDDocRecord-s in the store, subject to the given filter.
    async fn get_did_doc_records(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_doc_record_filter: &DIDDocRecordFilter,
    ) -> Result<Vec<DIDDocRecord>>;
    /// Get the DIDDocRecord-s whose DID documents' place in the did-documents.jsonl file for the given DID
    /// overlap with the specified range of bytes.  If None is provided for either range parameter, then it
    /// means "unbounded" In particular, if range_begin_inclusive_o is None, then the range starts at byte 0,
    /// and if range_end_exclusive_o is None, then the range ends at the end of the did-documents.jsonl file.
    /// Thus, if both are None, then the entire contents of the did-documents.jsonl file is returned.
    /// The returned vector is sorted by version_id.
    async fn get_did_doc_records_for_did_documents_jsonl_range(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        range_begin_inclusive_o: Option<u64>,
        range_end_exclusive_o: Option<u64>,
    ) -> Result<Vec<DIDDocRecord>>;
}
