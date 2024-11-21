use crate::{vjson_record::VJSONRecord, AlreadyExistsPolicy, Result};

#[async_trait::async_trait]
pub trait VJSONStorage: Clone + Send + Sync {
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

    /// Attempt to add a VJSON string (i.e. serialized VJSON) with the specified self-hash (which is its
    /// unique identifier) to the store.  If the self-hash already exists in the store, will return success
    /// or failure depending on the specified already_exists_policy.  Note that what is stored is the
    /// JCS-serialization of the VJSON value, regardless of the input format.  Implementations of this
    /// method must call VJSONRecord::validate_consistency, but are not required
    /// to perform full validation of the VJSON.
    async fn add_vjson_str(
        &self,
        transaction: &mut Self::Transaction<'_>,
        vjson_record: VJSONRecord,
        already_exists_policy: AlreadyExistsPolicy,
    ) -> Result<()>;

    /// Attempt to query the specified VJSON from the store, returning its JCS-serialized string upon success.
    /// Implementations of this method must call VJSONRecord::validate_consistency before returning, but are not
    /// required to perform full validation of the VJSON.
    async fn get_vjson_str(
        &self,
        transaction: &mut Self::Transaction<'_>,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<VJSONRecord>;
}
