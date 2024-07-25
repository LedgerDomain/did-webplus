use crate::{DIDDocRecord, Result};
use did_webplus::{DIDDocument, DIDStr};

#[async_trait::async_trait]
pub trait DIDDocStorage: Send + Sync {
    /// Defines the transaction type for this DID document storage implementation.  The transaction must rollback upon Drop.
    type Transaction<'t>: std::ops::Drop + Send + 't;

    /// Begin a new transaction.  If there is an existing transaction, then this creates a nested transaction under it.
    async fn begin_transaction<'s, 't: 's, 'u: 't>(
        &self,
        existing_transaction_o: Option<&'u mut Self::Transaction<'t>>,
    ) -> Result<Self::Transaction<'s>>;
    /// Commit a transaction.  If this is a nested transaction, then it should only commit the nested transaction's
    /// portion of the changes.
    async fn commit_transaction(&self, transaction: Self::Transaction<'_>) -> Result<()>;
    /// Rollback a transaction.  If this is a nested transaction, then it should only rollback the nested transaction's
    /// portion of the changes.
    async fn rollback_transaction(&self, transaction: Self::Transaction<'_>) -> Result<()>;

    /// Attempt to add a DID document to the store.  Will return an error if the DID document already exists.
    /// Note that did_document and did_document_jcs are redundant, and are expected to be consistent, but
    /// did_document_jcs is required because the specific string representation of the DID document is needed
    /// in order for the self-signature and self-hash to be verified.
    async fn add_did_document(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did_document: &DIDDocument,
        did_document_jcs: &str,
    ) -> Result<()>;
    /// Attempt to get a DIDDocRecord with a specific self-hash value from the store.  Will return None if
    /// the requested DIDDocRecord does not exist.
    async fn get_did_doc_record_with_self_hash(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<Option<DIDDocRecord>>;
    /// Attempt to get a DIDDocRecord with a specific version-id value from the store.  Will return None if
    /// the requested DIDDocRecord does not exist.
    async fn get_did_doc_record_with_version_id(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
        version_id: u32,
    ) -> Result<Option<DIDDocRecord>>;
    /// Get the latest DIDDocRecord for the specified DID from the store.  Will return None if the DID has
    /// no DIDDocRecord-s in this store.
    async fn get_latest_did_doc_record(
        &self,
        transaction: &mut Self::Transaction<'_>,
        did: &DIDStr,
    ) -> Result<Option<DIDDocRecord>>;
}
