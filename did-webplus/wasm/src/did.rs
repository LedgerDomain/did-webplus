use crate::{into_js_value, DIDResolver};
use std::ops::Deref;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

/// Resolve the given DID query using the given DIDResolver.  Returns the JCS-serialized DID document as a String.
#[wasm_bindgen]
pub fn did_resolve(did_query: String, did_resolver: &DIDResolver) -> js_sys::Promise {
    let did_resolver = did_resolver.clone();
    wasm_bindgen_futures::future_to_promise(async move {
        let did_document_jcs =
            did_webplus_cli_lib::did_resolve_string(did_query.as_str(), did_resolver.deref())
                .await
                .map_err(into_js_value)?;
        Ok(JsValue::from(did_document_jcs))
    })
}
