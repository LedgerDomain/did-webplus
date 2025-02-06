use crate::{into_js_value, Signer, VJSONResolver, VerifierResolver};
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

#[wasm_bindgen]
pub fn vjson_sign_and_self_hash(
    json_string: String,
    signer: &Signer,
    vjson_resolver: &VJSONResolver,
) -> js_sys::Promise {
    let signer = signer.clone();
    let vjson_resolver = vjson_resolver.clone();
    wasm_bindgen_futures::future_to_promise(async move {
        let mut vjson_value: serde_json::Value =
            serde_json::from_str(&json_string).map_err(into_js_value)?;
        // This is a bit of a hack for now.
        if signer.key_id_as_str().starts_with("did:key:") {
            did_webplus_cli_lib::did_key_sign_vjson(
                &mut vjson_value,
                signer.deref(),
                vjson_resolver.deref(),
            )
            .await
            .map_err(into_js_value)?;
        } else if signer.key_id_as_str().starts_with("did:webplus:") {
            unimplemented!("todo");
        } else {
            panic!("programmer error: unsupported DID method");
        }
        Ok(JsValue::from(
            serde_json_canonicalizer::to_string(&vjson_value).map_err(into_js_value)?,
        ))
    })
}

#[wasm_bindgen]
pub fn vjson_verify(
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
