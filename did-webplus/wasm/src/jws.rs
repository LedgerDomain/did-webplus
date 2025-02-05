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
// TODO: Figure out if #[wasm_bindgen] works directly on an async fn without the need for js_sys::Promise
#[wasm_bindgen]
pub fn jws_verify(jws: String, verifier_resolver: &VerifierResolver) -> js_sys::Promise {
    let verifier_resolver = verifier_resolver.clone();
    wasm_bindgen_futures::future_to_promise(async move {
        let jws = did_webplus_jws::JWS::try_from(jws).map_err(into_js_value)?;
        did_webplus_cli_lib::jws_verify(&jws, None, verifier_resolver.deref())
            .await
            .map_err(into_js_value)?;
        Ok(JsValue::null())
    })
}

/// Note that the return value will be null, but will throw an error if the verification fails.
// TODO: Support detached payload later.
// TEMP HACK: Just hardcode the did:key VerifierResolver for now.
#[wasm_bindgen]
pub fn jws_verify_temphack(jws: String) -> js_sys::Promise {
    wasm_bindgen_futures::future_to_promise(async move {
        let jws = did_webplus_jws::JWS::try_from(jws).map_err(into_js_value)?;
        did_webplus_cli_lib::jws_verify(&jws, None, &did_key::DIDKeyVerifierResolver)
            .await
            .map_err(into_js_value)?;
        Ok(JsValue::from("VALID"))
    })
}
