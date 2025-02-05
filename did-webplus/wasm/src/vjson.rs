use crate::{into_js_value, Result, VJSONResolver, VJSONStore, VerifierResolver};
use std::ops::Deref;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

#[wasm_bindgen]
pub fn vjson_default_schema() -> String {
    vjson_core::DEFAULT_SCHEMA.jcs.clone()
}

// TODO: Should this accept and return JsValue?  Or &str?
#[wasm_bindgen]
pub fn vjson_self_hash_temphack(json_string: String) -> js_sys::Promise {
    tracing::debug!("hippo 1; json_string: {}", json_string);
    wasm_bindgen_futures::future_to_promise(async move {
        let json_value: serde_json::Value =
            serde_json::from_str(&json_string).map_err(into_js_value)?;
        tracing::debug!("hippo 2");
        let vjson_store = VJSONStore::new_mock().await?;
        tracing::debug!("hippo 3");
        let vjson_resolver = vjson_store.as_resolver();
        tracing::debug!("hippo 4");
        let vjson_value = did_webplus_cli_lib::vjson_self_hash(json_value, vjson_resolver.deref())
            .await
            .map_err(into_js_value)?;
        tracing::debug!("hippo 5");
        // TODO: Probably use JCS here
        Ok(JsValue::from(vjson_value.to_string()))
    })
}

// TODO: Should this accept and return JsValue?  Or &str?
#[wasm_bindgen]
pub async fn vjson_self_hash(json_string: String, vjson_store: &VJSONStore) -> Result<String> {
    let json_value: serde_json::Value =
        serde_json::from_str(&json_string).map_err(into_js_value)?;
    let vjson_resolver = vjson_store.as_resolver();
    let vjson_value = did_webplus_cli_lib::vjson_self_hash(json_value, vjson_resolver.deref())
        .await
        .map_err(into_js_value)?;
    // TODO: Probably use JCS here
    Ok(vjson_value.to_string())
}

// TODO: Should this accept and return JsValue?  Or &str?
#[wasm_bindgen]
pub async fn vjson_verify(
    json_string: String,
    vjson_resolver: &VJSONResolver,
    verifier_resolver: &VerifierResolver,
) -> Result<JsValue> {
    // TODO: Using JsValue will presumably be more efficient.
    let json_value: serde_json::Value =
        serde_json::from_str(&json_string).map_err(into_js_value)?;
    let self_hash = did_webplus_cli_lib::vjson_verify(
        &json_value,
        vjson_resolver.deref(),
        verifier_resolver.deref(),
    )
    .await
    .map_err(into_js_value)?;
    Ok(JsValue::from(self_hash.into_string()))
}
