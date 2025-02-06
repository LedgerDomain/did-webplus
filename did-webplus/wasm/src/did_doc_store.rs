use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct DIDDocStore(did_webplus_doc_store::DIDDocStore);

impl DIDDocStore {
    pub fn into_inner(self) -> did_webplus_doc_store::DIDDocStore {
        self.0
    }
}

#[wasm_bindgen]
impl DIDDocStore {
    pub async fn new_mock() -> Self {
        let did_doc_storage_mock = did_webplus_doc_storage_mock::DIDDocStorageMock::new();
        let did_doc_store = did_webplus_doc_store::DIDDocStore::new(Arc::new(did_doc_storage_mock));
        Self(did_doc_store)
    }
}

impl std::ops::Deref for DIDDocStore {
    type Target = did_webplus_doc_store::DIDDocStore;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
