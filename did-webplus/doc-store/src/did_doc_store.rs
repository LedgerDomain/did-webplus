use crate::{parse_did_document, DIDDocRecord, DIDDocStorage, Result};
use did_webplus_core::{DIDDocument, DIDStr};
use std::sync::Arc;

#[derive(Clone)]
pub struct DIDDocStore {
    did_doc_storage_a: Arc<dyn DIDDocStorage>,
}

impl DIDDocStore {
    /// Create a new DIDDocStore using the given DIDDocStorage implementation.
    pub fn new(did_doc_storage_a: Arc<dyn DIDDocStorage>) -> Self {
        Self { did_doc_storage_a }
    }
    // NOTE: did_document and did_document_jcs are redundant, and this assumes that they're consistent.
    pub async fn validate_and_add_did_doc(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did_document: &DIDDocument,
        prev_did_document: Option<&DIDDocument>,
        did_document_jcs: &str,
    ) -> Result<()> {
        assert_eq!(
            parse_did_document(did_document_jcs)?,
            *did_document,
            "programmer error: body and did_document are inconsistent"
        );
        // This assumes that all stored DID documents have been validated inductively from the root!
        did_document.verify_nonrecursive(prev_did_document)?;
        self.did_doc_storage_a
            .add_did_document(transaction_o, did_document, did_document_jcs)
            .await?;
        Ok(())
    }
    pub async fn get_did_doc_record_with_self_hash(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Option<DIDDocRecord>> {
        self.did_doc_storage_a
            .get_did_doc_record_with_self_hash(transaction_o, did, self_hash)
            .await
    }
    pub async fn get_did_doc_record_with_version_id(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>> {
        self.did_doc_storage_a
            .get_did_doc_record_with_version_id(transaction_o, did, version_id)
            .await
    }
    pub async fn get_latest_did_doc_record(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>> {
        self.did_doc_storage_a
            .get_latest_did_doc_record(transaction_o, did)
            .await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for DIDDocStore {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        self.did_doc_storage_a.begin_transaction().await
    }
}
