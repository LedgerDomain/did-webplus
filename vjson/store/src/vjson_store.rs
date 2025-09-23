use crate::{
    error_invalid_vjson, error_record_corruption, vjson_record::VJSONRecord, Result, VJSONStorage,
};
use std::sync::Arc;
use vjson_core::{VJSONResolver, Validate, DEFAULT_SCHEMA};

#[derive(Clone, Copy, Debug)]
pub enum AlreadyExistsPolicy {
    DoNothing,
    Fail,
}

#[derive(Clone)]
pub struct VJSONStore {
    vjson_storage_a: Arc<dyn VJSONStorage>,
}

impl VJSONStore {
    /// Create a new VJSONStore using the given VJSONStorage implementation.
    pub async fn new(vjson_storage_a: Arc<dyn VJSONStorage>) -> Result<Self> {
        // TEMP HACK: Sanity check that the default schema is valid.
        // TODO: Need a VJSONResolver that's just the default schema, and an empty VerifierResolver.
        // use vjson_core::Validate;
        // vjson_core::DEFAULT_SCHEMA
        //     .value
        //     .validate_and_return_self_hash(vjson_resolver, verifier_resolver)
        //     .await
        //     .expect("programmer error: default schema is invalid");

        // Ensure that the Default schema is present in the store.
        tracing::info!(
            "Ensuring Default schema {} is present in storage.",
            vjson_core::DEFAULT_SCHEMA.vjson_url
        );
        let mut transaction_b = vjson_storage_a.begin_transaction().await?;
        let vjson_record = VJSONRecord {
            self_hash: DEFAULT_SCHEMA.self_hash.clone(),
            added_at: time::OffsetDateTime::now_utc(),
            vjson_jcs: DEFAULT_SCHEMA.jcs.clone(),
        };
        vjson_storage_a
            .add_vjson_str(
                Some(transaction_b.as_mut()),
                vjson_record,
                AlreadyExistsPolicy::DoNothing,
            )
            .await?;
        transaction_b.commit().await?;

        Ok(Self { vjson_storage_a })
    }

    // TODO: For convenience, make a typed version of this that takes a serde::Serialize type.

    /// Attempt to store a VJSON value (i.e. VJSON deserialized into serde_json::Value) to the store,
    /// returning its self-hash, which is its unique identifier.  If the self-hash already exists in
    /// the store, will return success or failure depending on the specified already_exists_policy.
    /// Note that what is stored is the JCS-serialization of the VJSON value.  Its self-hash is returned.
    pub async fn add_vjson_value(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        vjson_value: &serde_json::Value,
        verifier_resolver: &dyn verifier_resolver::VerifierResolver,
        already_exists_policy: AlreadyExistsPolicy,
        // TODO: optional expected schema
    ) -> Result<mbx::MBHash> {
        // This performs the full validation of VJSON against its schema.
        let self_hash = vjson_value
            .validate_and_return_self_hash(self, verifier_resolver)
            .await?;

        // Now that it's verified, JCS-serialize it for storage.
        let vjson_record = VJSONRecord {
            self_hash: self_hash.clone(),
            added_at: time::OffsetDateTime::now_utc(),
            vjson_jcs: serde_json_canonicalizer::to_string(&vjson_value).unwrap(),
        };
        tracing::trace!(
            "VJSONStore::add_vjson_value: vjson_record.vjson_jcs: {}",
            vjson_record.vjson_jcs
        );
        self.vjson_storage_a
            .add_vjson_str(transaction_o, vjson_record, already_exists_policy)
            .await?;

        Ok(self_hash)
    }
    /// Attempt to add a VJSON string (i.e. serialized VJSON) to the store, returning its self-hash, which
    /// is its unique identifier, and the JSON value parsed from the string.  Note that what is stored is the
    /// JCS-serialization of the VJSON value, regardless of the input format.  
    pub async fn add_vjson_str(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        vjson_str: &str,
        verifier_resolver: &dyn verifier_resolver::VerifierResolver,
        already_exists_policy: AlreadyExistsPolicy,
        // TODO: optional expected schema
    ) -> Result<(mbx::MBHash, serde_json::Value)> {
        tracing::trace!("VJSONStore::add_vjson_str: vjson_str: {}", vjson_str);
        // We have to parse the VJSON string to get the self-hash and to validate it.
        let vjson_value: serde_json::Value =
            serde_json::from_str(vjson_str).map_err(error_invalid_vjson)?;
        let self_hash = self
            .add_vjson_value(
                transaction_o,
                &vjson_value,
                verifier_resolver,
                already_exists_policy,
            )
            .await?;
        Ok((self_hash, vjson_value))
    }

    /// Attempt to query the specified VJSON from the store, returning its parsed serde_json::Value upon success.
    pub async fn get_vjson_value(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        self_hash: &mbx::MBHashStr,
        // TODO: optional expected schema
    ) -> Result<serde_json::Value> {
        let vjson_record = self.get_vjson_record(transaction_o, self_hash).await?;
        let vjson_value: serde_json::Value = serde_json::from_str(vjson_record.vjson_jcs.as_str())
            .map_err(error_record_corruption)?;
        Ok(vjson_value)
    }
    /// Attempt to query the specified VJSONRecord from the store.
    pub async fn get_vjson_record(
        &self,
        transaction_o: Option<&mut dyn storage_traits::TransactionDynT>,
        self_hash: &mbx::MBHashStr,
        // TODO: optional expected schema
    ) -> Result<VJSONRecord> {
        self.vjson_storage_a
            .get_vjson_str(transaction_o, self_hash)
            .await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl storage_traits::StorageDynT for VJSONStore {
    async fn begin_transaction(
        &self,
    ) -> storage_traits::Result<Box<dyn storage_traits::TransactionDynT>> {
        Ok(self.vjson_storage_a.begin_transaction().await?)
    }
}

/// Note that this impl requires that no transaction for the VJSONStore be active when this resolver is called,
/// otherwise the DB could lock (e.g. SQLite).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl VJSONResolver for VJSONStore {
    async fn resolve_vjson_string(&self, self_hash: &mbx::MBHashStr) -> vjson_core::Result<String> {
        let vjson_record = self
            .get_vjson_record(None, self_hash)
            .await
            .map_err(vjson_core::error_storage_error)?;
        Ok(vjson_record.vjson_jcs)
    }
}
