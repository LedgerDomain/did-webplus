use crate::{DIDResolver, Result, WalletBasedSigner, into_js_value};
use std::ops::Deref;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

/// Sign a generic JWT (this is NOT a VC or VP; use issue_vc_jwt or issue_vp_jwt for those purposes instead).
/// Claims is the content of the JWT, which should be a JSON object.
/// See <https://www.rfc-editor.org/rfc/rfc7519#section-4>.
#[wasm_bindgen]
pub async fn jwt_sign(claims: JsValue, wallet_based_signer: &WalletBasedSigner) -> Result<String> {
    let claims: ssi_claims::JWTClaims<serde_json::Value> =
        serde_wasm_bindgen::from_value(claims).map_err(into_js_value)?;
    let jwt = did_webplus_ssi::sign_jwt(&claims, wallet_based_signer.deref())
        .await
        .map_err(into_js_value)?;
    Ok(jwt.to_string())
}

/// Verify a generic JWT (this is NOT a VC or VP; use verify_vc_jwt or verify_vp_jwt for those purposes instead).
/// Use did_resolver to resolve the DID of the issuer of the JWT.
#[wasm_bindgen]
pub async fn jwt_verify(jwt: String, did_resolver: &DIDResolver) -> Result<JsValue> {
    let did_resolver_a = did_resolver.as_arc().clone();
    let jwt = did_webplus_ssi::verify_jwt(&jwt, did_resolver_a)
        .await
        .map_err(into_js_value)?;
    Ok(serde_wasm_bindgen::to_value(&jwt).map_err(into_js_value)?)
}
