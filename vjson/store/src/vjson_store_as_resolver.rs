use crate::VJSONStoreT;
use std::sync::{Arc, RwLock};

/// TEMP: Use a VJSONStore as a VJSONResolver.  Note that this is only sufficient for completely local resolution.
pub struct VJSONStoreAsResolver {
    pub vjson_store_l: Arc<RwLock<dyn VJSONStoreT>>,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl vjson_core::VJSONResolver for VJSONStoreAsResolver {
    async fn resolve_vjson_string(
        &self,
        self_hash: &selfhash::KERIHashStr,
    ) -> vjson_core::Result<String> {
        let vjson_store_g = self.vjson_store_l.read().unwrap();
        let vjson_record = vjson_store_g
            .get_vjson_record(self_hash)
            .await
            .map_err(vjson_core::error_storage_error)?;
        Ok(vjson_record.vjson_jcs)
    }
}
