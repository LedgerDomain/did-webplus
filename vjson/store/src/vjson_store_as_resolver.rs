use crate::VJSONStore;

/// TEMP: Use a VJSONStore as a VJSONResolver.  Note that this is only sufficient for completely local resolution.
#[derive(Clone)]
pub struct VJSONStoreAsResolver {
    pub vjson_store: VJSONStore,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl vjson_core::VJSONResolver for VJSONStoreAsResolver {
    async fn resolve_vjson_string(
        &self,
        self_hash: &selfhash::KERIHashStr,
    ) -> vjson_core::Result<String> {
        let vjson_record = self
            .vjson_store
            .get_vjson_record(None, self_hash)
            .await
            .map_err(vjson_core::error_storage_error)?;
        Ok(vjson_record.vjson_jcs)
    }
}
