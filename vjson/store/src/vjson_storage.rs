use crate::{vjson_record::VJSONRecord, AlreadyExistsPolicy, Result};

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait VJSONStorage: Send + storage_traits::StorageDynT + Sync {
    /// Attempt to add a VJSON string (i.e. serialized VJSON) with the specified self-hash (which is its
    /// unique identifier) to the store.  If the self-hash already exists in the store, will return success
    /// or failure depending on the specified already_exists_policy.  Note that what is stored is the
    /// JCS-serialization of the VJSON value, regardless of the input format.  Implementations of this
    /// method must call VJSONRecord::validate_consistency, but are not required
    /// to perform full validation of the VJSON.
    async fn add_vjson_str(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        vjson_record: VJSONRecord,
        already_exists_policy: AlreadyExistsPolicy,
    ) -> Result<()>;

    /// Attempt to query the specified VJSON from the store, returning its JCS-serialized string upon success.
    /// Implementations of this method must call VJSONRecord::validate_consistency before returning, but are not
    /// required to perform full validation of the VJSON.
    async fn get_vjson_str(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        self_hash: &selfhash::KERIHashStr,
    ) -> Result<VJSONRecord>;
}
