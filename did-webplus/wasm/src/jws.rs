use crate::{Result, VerifierResolver, WalletBasedSigner, into_js_value};
use std::ops::Deref;
use wasm_bindgen::prelude::wasm_bindgen;

/// Sign a JWS.  payload_string specifies the payload of the JWS (the payload should be bytes (Vec<u8>), but
/// for now just use a String).  payload_presence specifies whether the payload is attached or detached.
/// payload_encoding specifies whether the payload is encoded or unencoded.
#[wasm_bindgen]
pub async fn jws_sign(
    payload_string: String,
    payload_presence: did_webplus_jws::JWSPayloadPresence,
    payload_encoding: did_webplus_jws::JWSPayloadEncoding,
    wallet_based_signer: &WalletBasedSigner,
) -> Result<String> {
    let jws = did_webplus_jws::JWS::async_signed(
        wallet_based_signer.key_fully_qualified().to_string(),
        &mut payload_string.as_bytes(),
        payload_presence,
        payload_encoding,
        wallet_based_signer.deref(),
    )
    .await
    .map_err(into_js_value)?;
    Ok(jws.into_string())
}

/// Verify a JWS, optionally specifying a detached payload (which should be None/null if the payload is attached).
/// Will return error if verification fails.
#[wasm_bindgen]
pub async fn jws_verify(
    jws: String,
    detached_payload_o: Option<String>,
    verifier_resolver: &VerifierResolver,
) -> Result<()> {
    tracing::debug!("jws_verify(jws: {:?})", jws);
    let verifier_resolver = verifier_resolver.clone();
    let jws = did_webplus_jws::JWS::try_from(jws).map_err(into_js_value)?;
    let mut detached_payload_buffer_o = detached_payload_o.as_ref().map(|x| x.as_bytes());
    did_webplus_cli_lib::jws_verify(
        &jws,
        detached_payload_buffer_o
            .as_mut()
            .map(|x| x as &mut dyn std::io::Read),
        verifier_resolver.deref(),
    )
    .await
    .map_err(|e| {
        tracing::error!("jws_verify FAILED");
        into_js_value(e)
    })?;
    tracing::info!("jws_verify SUCCEEDED");
    Ok(())
}
