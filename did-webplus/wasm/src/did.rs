use crate::{DIDResolver, into_js_value};
use std::ops::Deref;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

/// Resolve the given DID query using the given DIDResolver.  Returns the JCS-serialized DID document as a String.
#[wasm_bindgen]
pub fn did_resolve(did_query: String, did_resolver: &DIDResolver) -> js_sys::Promise {
    let did_resolver = did_resolver.clone();
    // TEMP HACK
    let did_resolution_options = did_webplus_core::DIDResolutionOptions::no_metadata(false);
    wasm_bindgen_futures::future_to_promise(async move {
        let (did_document_jcs, _did_document_metadata, _did_resolution_metadata) =
            did_webplus_cli_lib::did_resolve_string(
                did_query.as_str(),
                did_resolver.deref(),
                did_resolution_options,
            )
            .await
            .map_err(into_js_value)?;
        Ok(JsValue::from(did_document_jcs))
    })
}
