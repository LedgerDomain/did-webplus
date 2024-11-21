use crate::{
    error_invalid_vjson, error_record_corruption, vjson_record::VJSONRecord, Result, VJSONStorage,
    Validate,
};

#[derive(Clone, Copy, Debug)]
pub enum AlreadyExistsPolicy {
    DoNothing,
    Fail,
}

#[derive(Clone)]
pub struct VJSONStore<Storage: VJSONStorage> {
    storage: Storage,
}

impl<Storage: VJSONStorage> VJSONStore<Storage> {
    /// Create a new VJSONStore using the given VJSONStorage implementation.
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

    // TODO: For convenience, make a typed version of this that takes a serde::Serialize type.

    /// Attempt to store a VJSON value (i.e. VJSON deserialized into serde_json::Value) to the store,
    /// returning its self-hash, which is its unique identifier.  If the self-hash already exists in
    /// the store, will return success or failure depending on the specified already_exists_policy.
    /// Note that what is stored is the JCS-serialization of the VJSON value.  Its self-hash is returned.
    pub async fn add_vjson_value(
        &self,
        transaction: &mut Storage::Transaction<'_>,
        vjson_value: &serde_json::Value,
        already_exists_policy: AlreadyExistsPolicy,
        // TODO: optional expected schema
    ) -> Result<selfhash::KERIHash> {
        // This performs the full validation of VJSON against its schema.
        let self_hash = vjson_value
            .validate_and_return_self_hash(&mut *transaction, self)
            .await?;

        // Now that it's verified, JCS-serialize it for storage.
        let vjson_record = VJSONRecord {
            self_hash: self_hash.clone(),
            added_at: time::OffsetDateTime::now_utc(),
            vjson_jcs: serde_json_canonicalizer::to_string(&vjson_value).unwrap(),
        };
        log::trace!(
            "VJSONStore::add_vjson_value: vjson_record.vjson_jcs: {}",
            vjson_record.vjson_jcs
        );
        self.storage
            .add_vjson_str(transaction, vjson_record, already_exists_policy)
            .await?;

        Ok(self_hash)
    }
    /// Attempt to add a VJSON string (i.e. serialized VJSON) to the store, returning its self-hash, which
    /// is its unique identifier.  Will return an error if its self-hash value already exists in the store.
    /// Note that what is stored is the JCS-serialization of the VJSON value, regardless of the input format.  
    pub async fn add_vjson_str(
        &self,
        transaction: &mut Storage::Transaction<'_>,
        vjson_str: &str,
        already_exists_policy: AlreadyExistsPolicy,
        // TODO: optional expected schema
    ) -> Result<(selfhash::KERIHash, serde_json::Value)> {
        log::trace!("VJSONStore::add_vjson_str: vjson_str: {}", vjson_str);
        // We have to parse the VJSON string to get the self-hash and to validate it.
        let vjson_value: serde_json::Value =
            serde_json::from_str(vjson_str).map_err(error_invalid_vjson)?;
        let self_hash = self
            .add_vjson_value(transaction, &vjson_value, already_exists_policy)
            .await?;
        Ok((self_hash, vjson_value))
    }

    /// Attempt to query the specified VJSON from the store, returning its parsed serde_json::Value upon success.
    pub async fn get_vjson_value(
        &self,
        transaction: &mut Storage::Transaction<'_>,
        self_hash: &selfhash::KERIHashStr,
        // TODO: optional expected schema
    ) -> Result<serde_json::Value> {
        let vjson_record = self.get_vjson_str(transaction, self_hash).await?;
        let vjson_value: serde_json::Value = serde_json::from_str(vjson_record.vjson_jcs.as_str())
            .map_err(error_record_corruption)?;
        Ok(vjson_value)
    }
    /// Attempt to query the specified VJSONRecord from the store.
    pub async fn get_vjson_str(
        &self,
        transaction: &mut Storage::Transaction<'_>,
        self_hash: &selfhash::KERIHashStr,
        // TODO: optional expected schema
    ) -> Result<VJSONRecord> {
        self.storage.get_vjson_str(transaction, self_hash).await
    }
}
