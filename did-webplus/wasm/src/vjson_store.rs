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
    pub fn as_resolver(&self) -> VJSONResolver {
        VJSONResolver::new(Arc::new(self.0.clone()))
    }
}
