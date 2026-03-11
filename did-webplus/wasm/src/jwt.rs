use crate::{DIDResolver, Result, WalletBasedSigner, into_js_value};
use std::ops::Deref;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[wasm_bindgen]
pub async fn jwt_sign(claims: JsValue, wallet_based_signer: &WalletBasedSigner) -> Result<String> {
    let claims: ssi_claims::JWTClaims<serde_json::Value> =
        serde_wasm_bindgen::from_value(claims).map_err(into_js_value)?;
    let jwt = did_webplus_ssi::sign_jwt(&claims, wallet_based_signer.deref())
        .await
        .map_err(into_js_value)?;
    Ok(jwt.to_string())
}

#[wasm_bindgen]
pub async fn jwt_verify(jwt: String, did_resolver: &DIDResolver) -> Result<JsValue> {
    let did_resolver_a = did_resolver.as_arc().clone();
    let jwt = did_webplus_ssi::verify_jwt(&jwt, did_resolver_a)
        .await
        .map_err(into_js_value)?;
    Ok(serde_wasm_bindgen::to_value(&jwt).map_err(into_js_value)?)
}
