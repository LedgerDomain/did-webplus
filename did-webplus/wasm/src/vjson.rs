use crate::{into_js_value, VJSONResolver, VerifierResolver};
use std::ops::Deref;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn vjson_default_schema() -> String {
    vjson_core::DEFAULT_SCHEMA.jcs.clone()
}

#[wasm_bindgen]
pub fn vjson_self_hash(json_string: String, vjson_resolver: &VJSONResolver) -> js_sys::Promise {
    let vjson_resolver = vjson_resolver.clone();
    wasm_bindgen_futures::future_to_promise(async move {
        let json_value: serde_json::Value =
            serde_json::from_str(&json_string).map_err(into_js_value)?;
        let vjson_value = did_webplus_cli_lib::vjson_self_hash(json_value, vjson_resolver.deref())
            .await
            .map_err(into_js_value)?;
        Ok(JsValue::from(
            serde_json_canonicalizer::to_string(&vjson_value).map_err(into_js_value)?,
        ))
    })
}

// TODO: vjson_sign which takes a Signer.

#[wasm_bindgen]
pub async fn vjson_verify(
    json_string: String,
    vjson_resolver: &VJSONResolver,
    verifier_resolver: &VerifierResolver,
) -> js_sys::Promise {
    let vjson_resolver = vjson_resolver.clone();
    let verifier_resolver = verifier_resolver.clone();
    wasm_bindgen_futures::future_to_promise(async move {
        // TODO: Using JsValue will presumably be more efficient.
        let json_value: serde_json::Value =
            serde_json::from_str(&json_string).map_err(into_js_value)?;
        let self_hash = did_webplus_cli_lib::vjson_verify(
            &json_value,
            vjson_resolver.deref(),
            verifier_resolver.deref(),
        )
        .await
        .map_err(|e| {
            tracing::error!("vjson_verify FAILED");
            into_js_value(e)
        })?;
        tracing::info!("vjson_verify SUCCEEDED");
        Ok(JsValue::from(self_hash.into_string()))
    })
}
