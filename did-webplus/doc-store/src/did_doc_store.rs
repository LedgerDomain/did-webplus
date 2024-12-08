use crate::{parse_did_document, DIDDocRecord, DIDDocStorage, Result};
use did_webplus_core::{DIDDocument, DIDStr};

#[derive(Clone)]
pub struct DIDDocStore<Storage: DIDDocStorage> {
    storage: Storage,
}

impl<Storage: DIDDocStorage> DIDDocStore<Storage> {
    /// Create a new DIDDocStore using the given DIDDocStorage implementation.
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }
    /// Begin a transaction for the underlying storage, creating a nested transaction if there is
    /// a transaction already in existence.  This is needed for all storage operations.
    pub async fn begin_transaction<'s, 't: 's, 'u: 't>(
        &self,
        existing_transaction_o: Option<&'u mut Storage::Transaction<'t>>,
    ) -> Result<Storage::Transaction<'s>> {
        self.storage.begin_transaction(existing_transaction_o).await
    }
    /// Commit a transaction for the underlying storage.  This should be done after all storage operations,
    /// even if they're read-only (principle of least-surprise).
    pub async fn commit_transaction(&self, transaction: Storage::Transaction<'_>) -> Result<()> {
        self.storage.commit_transaction(transaction).await
    }
    /// Rollback a transaction for the underlying storage.  This should be done if an error occurs during
    /// storage operations.
    pub async fn rollback_transaction(&self, transaction: Storage::Transaction<'_>) -> Result<()> {
        self.storage.rollback_transaction(transaction).await
    }
    // NOTE: did_document and did_document_jcs are redundant, and this assumes that they're consistent.
    pub async fn validate_and_add_did_doc(
        &self,
        transaction: &mut Storage::Transaction<'_>,
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
        self.storage
            .add_did_document(transaction, did_document, did_document_jcs)
            .await?;
        Ok(())
    }
    pub async fn get_did_doc_record_with_self_hash(
        &self,
        transaction: &mut Storage::Transaction<'_>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Option<DIDDocRecord>> {
        self.storage
            .get_did_doc_record_with_self_hash(transaction, did, self_hash)
            .await
    }
    pub async fn get_did_doc_record_with_version_id(
        &self,
        transaction: &mut Storage::Transaction<'_>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>> {
        self.storage
            .get_did_doc_record_with_version_id(transaction, did, version_id)
            .await
    }
    pub async fn get_latest_did_doc_record(
        &self,
        transaction: &mut Storage::Transaction<'_>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>> {
        self.storage
            .get_latest_did_doc_record(transaction, did)
            .await
    }
    // pub async fn did_exists(&self, did: &DIDStr) -> Result<bool> {
    //     let mut transaction = self.storage.begin_transaction().await?;
    //     let did_doc_record_o = self
    //         .storage
    //         .get_latest_did_document(&mut transaction, did)
    //         .await?;
    //     transaction.commit().await?;
    //     Ok(did_doc_record_o.is_some())
    // }
}
