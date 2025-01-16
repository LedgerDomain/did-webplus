use crate::{AlreadyExistsPolicy, Result, VJSONRecord};

/// This provides VJSONStore functionality through an object-safe trait.
/// Note that it provides no control over transactions.  If this is deemed to be needed,
/// it can be implemented later.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait VJSONStoreT: Send + Sync {
    /// Attempt to store a VJSON value (i.e. VJSON deserialized into serde_json::Value) to the store,
    /// returning its self-hash, which is its unique identifier.  If the self-hash already exists in
    /// the store, will return success or failure depending on the specified already_exists_policy.
    /// Note that what is stored is the JCS-serialization of the VJSON value.  Its self-hash is returned.
    async fn add_vjson_value(
        &self,
        vjson_value: &serde_json::Value,
        verifier_resolver: &dyn verifier_resolver::VerifierResolver,
        already_exists_policy: AlreadyExistsPolicy,
        // TODO: optional expected schema
    ) -> Result<selfhash::KERIHash>;
    /// Attempt to add a VJSON string (i.e. serialized VJSON) to the store, returning its self-hash, which
    /// is its unique identifier, and the JSON value parsed from the string.  Note that what is stored is the
    /// JCS-serialization of the VJSON value, regardless of the input format.  
    async fn add_vjson_str(
        &self,
        vjson_str: &str,
        verifier_resolver: &dyn verifier_resolver::VerifierResolver,
        already_exists_policy: AlreadyExistsPolicy,
        // TODO: optional expected schema
    ) -> Result<(selfhash::KERIHash, serde_json::Value)>;
    /// Attempt to query the specified VJSON from the store, returning its parsed serde_json::Value upon success.
    async fn get_vjson_value(
        &self,
        self_hash: &selfhash::KERIHashStr,
        // TODO: optional expected schema
    ) -> Result<serde_json::Value>;
    /// Attempt to query the specified VJSONRecord from the store.
    async fn get_vjson_record(
        &self,
        self_hash: &selfhash::KERIHashStr,
        // TODO: optional expected schema
    ) -> Result<VJSONRecord>;
}

// /// Note that this impl requires that no transaction for the VJSONStore be active when this resolver is called,
// /// otherwise the DB could lock (e.g. SQLite).
// #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
// impl<Store: VJSONStoreT> VJSONResolver for Store {
//     async fn resolve_vjson_string(
//         &self,
//         self_hash: &selfhash::KERIHashStr,
//     ) -> vjson_core::Result<String> {
//         let vjson_record = self
//             .get_vjson_record(self_hash)
//             .await
//             .map_err(vjson_core::error_storage_error)?;
//         Ok(vjson_record.vjson_jcs)
//     }
// }
