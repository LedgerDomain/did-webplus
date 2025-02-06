use crate::{into_js_value, Result, Signer, VerifierResolver};
use std::ops::Deref;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

/// NOTE: The payload should be bytes (Vec<u8>), but for now just use a String.
#[wasm_bindgen]
pub fn jws_sign(
    payload_string: String,
    payload_presence: did_webplus_jws::JWSPayloadPresence,
    payload_encoding: did_webplus_jws::JWSPayloadEncoding,
    signer: &Signer,
) -> Result<String> {
    let jws = did_webplus_jws::JWS::signed(
        signer.key_id(),
        &mut payload_string.as_bytes(),
        payload_presence,
        payload_encoding,
        signer.deref(),
    )
    .map_err(into_js_value)?;
    Ok(jws.into_string())
}

/// Note that the return value will be null, but will throw an error if the verification fails.
// TODO: Support detached payload later.
#[wasm_bindgen]
pub fn jws_verify(jws: String, verifier_resolver: &VerifierResolver) -> js_sys::Promise {
    tracing::debug!("jws_verify(jws: {:?})", jws);
    let verifier_resolver = verifier_resolver.clone();
    wasm_bindgen_futures::future_to_promise(async move {
        let jws = did_webplus_jws::JWS::try_from(jws).map_err(into_js_value)?;
        did_webplus_cli_lib::jws_verify(&jws, None, verifier_resolver.deref())
            .await
            .map_err(|e| {
                tracing::error!("jws_verify FAILED");
                into_js_value(e)
            })?;
        tracing::info!("jws_verify SUCCEEDED");
        Ok(JsValue::null())
    })
}
