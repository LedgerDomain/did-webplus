use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct VJSONResolver(Arc<dyn vjson_core::VJSONResolver>);

impl VJSONResolver {
    pub fn new(vjson_resolver_a: Arc<dyn vjson_core::VJSONResolver>) -> Self {
        Self(vjson_resolver_a)
    }
}

impl std::ops::Deref for VJSONResolver {
    type Target = dyn vjson_core::VJSONResolver;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
