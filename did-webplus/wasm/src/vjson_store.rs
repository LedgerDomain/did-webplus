use crate::{into_js_value, Result, VJSONResolver};
use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct VJSONStore(vjson_store::VJSONStore);

#[wasm_bindgen]
impl VJSONStore {
    pub async fn new_mock() -> Result<Self> {
        let vjson_storage_mock = vjson_storage_mock::VJSONStorageMock::new();
        let vjson_store = vjson_store::VJSONStore::new(Arc::new(vjson_storage_mock))
            .await
            .map_err(into_js_value)?;
        Ok(Self(vjson_store))
    }
}

impl VJSONStore {
    pub fn as_resolver(&self) -> VJSONResolver {
        let vjson_store_as_resolver = vjson_store::VJSONStoreAsResolver {
            vjson_store: self.0.clone(),
        };
        VJSONResolver::new(Arc::new(vjson_store_as_resolver))
    }
}
